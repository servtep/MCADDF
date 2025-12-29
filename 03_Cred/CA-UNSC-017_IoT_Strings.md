# [CA-UNSC-017]: IoT Device Connection Strings Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-017 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure IoT Hub |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure IoT Hub uses connection strings for device authentication. If an attacker gains access to a device's local storage (firmware extraction) or the source code of the IoT application, they can extract the `HostName=...;DeviceId=...;SharedAccessKey=...` string. This allows impersonating the device to send fake telemetry or receive cloud-to-device commands.
- **Attack Surface:** IoT Firmware and Source Code.
- **Business Impact:** **Data Integrity Loss**. Spoofing telemetry (e.g., temperature data in a factory).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Physical access to device or Read access to repo.
- **Tools:**
    - `strings`
    - [TruffleHog](https://github.com/trufflesecurity/trufflehog)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
Search for the pattern `SharedAccessKey=`.
```bash
grep -r "SharedAccessKey=" .
```

**Step 2: Impersonation**
Use the Azure IoT extension to send messages.
```bash
az iot device simulate -d "MyDevice" -n "MyHub" --connection-string "HostName=..."
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Monitor
| Source | Event | Filter Logic |
|---|---|---|
| **IoT Hub** | `DeviceConnect` | Simultaneous connections from different IPs for the same DeviceID. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Authentication:** Use **X.509 Certificates** or **TPM Attestation** instead of symmetric keys (Connection Strings) for device auth.
*   **Rotation:** Regenerate the Shared Access Key for the compromised device in IoT Hub.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004] (IoT Device Compromise)
> **Next Logical Step:** [EXFIL-IOT-001]
