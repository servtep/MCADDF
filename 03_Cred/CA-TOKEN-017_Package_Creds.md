# [CA-TOKEN-017]: Package Source Credential Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-017 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | npm / pip / Maven |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Similar to NuGet, npm (`.npmrc`) and pip (`pip.conf`) store authentication tokens for private registries. These are often plaintext.
- **Attack Surface:** Developer Workstation.
- **Business Impact:** **Supply Chain Attack**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read access.
- **Tools:** `cat`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
```bash
cat ~/.npmrc
# Look for //registry.npmjs.org/:_authToken=...
```

**Step 2: Abuse**
```bash
npm publish
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Registry Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Registry** | `Publish` | Publish events from new IPs. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **2FA:** Enforce 2FA for `npm publish`. This renders the token useless for publishing without the second factor.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-SUPPLY-001]
