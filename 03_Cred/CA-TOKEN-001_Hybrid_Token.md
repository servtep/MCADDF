# [CA-TOKEN-001]: Hybrid AD Cloud Token Theft (CVE-2023-32315)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-001 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD |
| **Severity** | **Critical** |
| **CVE** | **CVE-2023-32315** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Attackers exploit the Azure AD Connect (AADC) Password Hash Sync mechanism or Pass-Through Authentication (PTA) agent. Specifically, vulnerabilities or misconfigurations allow an attacker on the AADC server to extract the `MSOL_` account credentials or inject a malicious PTA agent. This grants the ability to intercept plaintext passwords (PTA) or sync malicious hashes to the cloud.
- **Attack Surface:** Azure AD Connect Server.
- **Business Impact:** **Hybrid Identity Compromise**. Interception of all user logins or syncing known passwords to cloud accounts.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Local Admin on AADC Server.
- **Tools:**
    - [AADInternals](https://github.com/Gerenios/AADInternals)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Install PTA Spy (AADInternals)**
Inject a DLL into the PTA agent to harvest credentials in plaintext as they are verified.
```powershell
Install-AADIntPTASpy
```

**Step 2: Harvest**
View captured credentials.
```powershell
Get-AADIntPTASpyLog
```
*Output: `Timestamp | Username | Password`*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4688 | Process injection into `AzureADConnectAuthenticationAgentService.exe`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Tier 0:** Treat AADC servers as Tier 0 assets (same security as Domain Controllers).
*   **Monitoring:** Alert on any DLL injection or service restart on AADC servers.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001]
> **Next Logical Step:** [LAT-CLOUD-001]
