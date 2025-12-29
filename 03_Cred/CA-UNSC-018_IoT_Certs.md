# [CA-UNSC-018]: IoT Device Certificates Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-018 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure IoT Hub |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** When using X.509 authentication, the private key is ideally stored in a secure element (TPM/HSM). However, developers often store the `.pem` or `.key` file on the device filesystem. Extracting this key allows an attacker to clone the device identity.
- **Attack Surface:** IoT Device Filesystem (`/etc/iotedge/`).
- **Business Impact:** **Device Cloning**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Root on IoT Device.
- **Tools:**
    - `cat`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
Look for keys configured in `config.yaml` (IoT Edge).
```bash
cat /etc/iotedge/config.yaml | grep "device_ca_pk"
```

**Step 2: Exfiltration**
Copy the private key file.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure IoT Hub
| Source | Event | Filter Logic |
|---|---|---|
| **IoT Hub** | `DeviceConnect` | Alert on the same certificate being used from a new, unexpected IP location. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Hardware Security:** Mandate the use of **TPM 2.0** or **HSM** integration via the Azure IoT Identity Service (IS). Do not use file-based keys.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [EXFIL-IOT-001]
