# REC-CLOUD-007: Azure Key Vault Access Enumeration

**SERVTEP ID:** REC-CLOUD-007  
**Technique Name:** Azure Key Vault access enumeration  
**MITRE ATT&CK Mapping:** T1552.001 (Unsecured Credentials - Credentials In Files)  
**CVE Reference:** CVE-2023-28432  
**Environment:** Entra ID  
**Severity:** Critical  
**Difficulty:** Medium  

---

## Executive Summary

Azure Key Vault stores critical secrets, keys, and certificates but is often misconfigured with overly permissive access policies. Attackers enumerate Key Vaults to discover credential stores and identify paths to compromise sensitive data. A compromised Key Vault exposes database connection strings, API keys, SSL certificates, and service principal credentials—enabling full environment compromise.

---

## Objective

Enumerate and assess Key Vault security to:
- Discover all Key Vaults accessible to current user
- Identify Key Vaults with weak access policies
- Enumerate secrets, keys, and certificates stored in vaults
- Find Key Vaults accessible via managed identities
- Identify vaults with public network access enabled
- Discover access policies that can be modified
- Map Key Vault usage across applications
- Identify vaults with disabled purge protection (can delete secrets)

---

## Prerequisites

- Azure subscription access (Reader role minimum)
- Azure CLI or PowerShell with Az.KeyVault module
- Entra ID credentials
- Network access to key.azure.io endpoints

---

## Execution Procedures

### Method 1: PowerShell Key Vault Enumeration

**Step 1:** Discover all Key Vaults
```powershell
# Connect to Azure
Connect-AzAccount

# Get all Key Vaults in subscription
Get-AzKeyVault | Select-Object VaultName, ResourceGroupName, Location

# Get Key Vaults across all subscriptions
Get-AzSubscription | ForEach-Object {
  Set-AzContext -Subscription $_
  Get-AzKeyVault
} | Export-Csv all_key_vaults.csv
```

**Step 2:** Analyze Key Vault access policies
```powershell
# Get access policies for each Key Vault
Get-AzKeyVault | ForEach-Object {
  $vault = $_
  Write-Host "Key Vault: $($vault.VaultName)"
  
  # Get access policies
  Get-AzKeyVaultAccessPolicy -VaultName $vault.VaultName -ResourceGroupName $vault.ResourceGroupName |
    ForEach-Object {
      Write-Host "  Principal: $($_.DisplayName)"
      Write-Host "    Permissions: $($_.PermissionsToKeys, $_.PermissionsToSecrets, $_.PermissionsToCertificates)"
    }
}
```

**Step 3:** Identify Key Vaults with overly permissive policies
```powershell
# Find Key Vaults allowing 'Get' on all secrets (potential data exposure)
Get-AzKeyVault | ForEach-Object {
  $vault = $_
  $policies = Get-AzKeyVaultAccessPolicy -VaultName $vault.VaultName -ResourceGroupName $vault.ResourceGroupName
  
  $risky = $policies | Where-Object {
    $_.PermissionsToSecrets -contains "Get" -and 
    $_.PermissionsToSecrets -contains "*"  # Wildcard permissions
  }
  
  if ($risky.Count -gt 0) {
    Write-Host "[HIGH RISK] $($vault.VaultName) has overly permissive policies"
  }
}

# Find Key Vaults accessible via managed identities
Get-AzKeyVault | ForEach-Object {
  $vault = $_
  $policies = Get-AzKeyVaultAccessPolicy -VaultName $vault.VaultName -ResourceGroupName $vault.ResourceGroupName
  
  $policies | Where-Object {$_.ObjectId -match "-"} | # MI typically has GUID principals
    ForEach-Object {Write-Host "MI Access: $($vault.VaultName) -> $($_.DisplayName)"}
}
```

### Method 2: Enumerate Secrets in Key Vaults

**Step 1:** List secrets in accessible vaults
```powershell
# Get all secrets in vault
Get-AzKeyVault | ForEach-Object {
  $vault = $_
  Write-Host "Vault: $($vault.VaultName)"
  
  try {
    Get-AzKeyVaultSecret -VaultName $vault.VaultName |
      Select-Object Name, Expires | 
      ForEach-Object {Write-Host "  Secret: $($_.Name)"}
  } catch {
    Write-Host "  [ACCESS DENIED]"
  }
}

# Get secret values (if permissions allow)
Get-AzKeyVaultSecret -VaultName <vault-name> -Name <secret-name> |
  Select-Object Value

# Export secret names and metadata
$secrets = Get-AzKeyVaultSecret -VaultName <vault-name>
$secrets | Export-Csv vault_secrets.csv
```

**Step 2:** Enumerate keys and certificates
```powershell
# Get all keys in vault
Get-AzKeyVaultKey -VaultName <vault-name> | 
  Select-Object Name, KeyType, Enabled, Expires

# Get all certificates
Get-AzKeyVaultCertificate -VaultName <vault-name> | 
  Select-Object Name, Thumbprint, Expires

# Find certificates about to expire (potential impact)
Get-AzKeyVaultCertificate -VaultName <vault-name> |
  Where-Object {$_.Expires -lt (Get-Date).AddDays(30)}
```

### Method 3: Azure CLI Key Vault Enumeration

**Step 1:** List and analyze vaults via CLI
```bash
# Get all Key Vaults
az keyvault list --output table

# Get details for specific vault
az keyvault show --name <vault-name> --query "{Name:name, Location:location, AccessPolicy:properties.accessPolicies}"

# Get secrets in vault
az keyvault secret list --vault-name <vault-name> --output table

# Get secret values
az keyvault secret show --vault-name <vault-name> --name <secret-name> --query value -o tsv
```

**Step 2:** Check network access and firewall configuration
```bash
# Get Key Vault network rules
az keyvault network-rule list --vault-name <vault-name>

# Check if vault allows public access
az keyvault show --name <vault-name> --query properties.publicNetworkAccess
```

### Method 4: Key Vault Access Policy Modification Paths

**Step 1:** Identify who can modify access policies
```powershell
# Get Key Vault's access policies
$vault = Get-AzKeyVault -VaultName <vault-name>

# Check if current user can modify policies
$policies = $vault.AccessPolicies
$policies | Where-Object {
  $_.ObjectId -eq (Get-AzContext).Account.ExtendedProperties.HomeAccountId
} | ForEach-Object {
  if ($_.PermissionsToSecrets -contains "List" -or 
      $_.PermissionsToSecrets -contains "*") {
    Write-Host "[MODIFIABLE] Current user can modify vault $($vault.VaultName)"
  }
}

# Find managed identities that can be modified (to add Key Vault permissions)
Get-AzUserAssignedIdentity | ForEach-Object {
  if (# Check if current user can modify this MI
      (Get-AzRoleAssignment -ObjectId $_.PrincipalId | Where-Object {$_.RoleDefinitionName -eq "Owner"})) {
    Write-Host "[MODIFIABLE MI] $($_.Name) could be assigned Key Vault access"
  }
}
```

### Method 5: Comprehensive Key Vault Security Audit

**Step 1:** Full enumeration and risk assessment
```powershell
# Comprehensive Key Vault audit
$auditResults = @{
  "KeyVaults" = @()
  "HighRiskSecrets" = @()
  "AccessPolicyRisks" = @()
  "NetworkAccessIssues" = @()
}

# Enumerate all Key Vaults
Get-AzKeyVault | ForEach-Object {
  $vault = $_
  $vaultAudit = [PSCustomObject]@{
    Name = $vault.VaultName
    Location = $vault.Location
    PurgeProtection = $vault.EnablePurgeProtection
    PublicAccess = $vault.PublicNetworkAccess
    SoftDelete = $vault.EnableSoftDelete
  }
  
  $auditResults["KeyVaults"] += $vaultAudit
  
  # Check secrets
  try {
    Get-AzKeyVaultSecret -VaultName $vault.VaultName | ForEach-Object {
      if ($_.Expires -lt (Get-Date).AddDays(30) -and $_.Expires -ne $null) {
        $auditResults["HighRiskSecrets"] += @{
          Vault = $vault.VaultName
          Secret = $_.Name
          ExpiresIn = [math]::Ceiling(($_.Expires - (Get-Date)).TotalDays)
        }
      }
    }
  } catch {}
  
  # Check access policies
  Get-AzKeyVaultAccessPolicy -VaultName $vault.VaultName -ResourceGroupName $vault.ResourceGroupName |
    ForEach-Object {
      if ($_.PermissionsToSecrets -contains "List" -or 
          $_.PermissionsToSecrets -contains "*") {
        $auditResults["AccessPolicyRisks"] += @{
          Vault = $vault.VaultName
          Principal = $_.DisplayName
          RiskLevel = "High"
        }
      }
    }
}

# Export audit results
$auditResults | ConvertTo-Json | Out-File keyvault_audit.json
```

---

## Technical Deep Dive

### Key Vault Permissions

**Secret Permissions:**
- Get - Read secret values
- List - Enumerate secrets
- Set - Create/modify secrets
- Delete - Remove secrets
- Backup/Restore - Export/import secrets

**Access Control Models:**
- Vault access policies (legacy, RBAC-compatible)
- Azure RBAC (recommended)
- Managed identity assignments

---

## Detection Strategies (Blue Team)

### Key Vault Activity Monitoring

1. **Azure Activity Logging**
   - Monitor secret GET operations
   - Alert on access policy modifications
   - Track vault creation and deletion

2. **Azure Monitor Alerts**
   - Secret access spikes
   - Failed authentication attempts
   - Policy changes

---

## Mitigation Strategies

1. **Immediate Actions**
   - Audit Key Vault access policies
   - Rotate secrets that may be compromised
   - Enable purge protection

2. **Detection & Response**
   - Enable Key Vault logging
   - Monitor secret access
   - Alert on unusual patterns

3. **Long-term Security**
   - Use Azure RBAC instead of access policies
   - Implement managed identities
   - Regular secret rotation
   - Enable firewall and network isolation

---

## References & Further Reading

- [Azure Key Vault Security Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features)
- [Key Vault Access Control](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)

---

## Related SERVTEP Techniques

- **CA-UNSC-007**: Azure Key Vault secret extraction
- **REC-CLOUD-006**: Service principal enumeration

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Vault discovery | 1-2 minutes | Easy |
| Access policy analysis | 3-5 minutes | Medium |
| Secret enumeration | 2-5 minutes | Medium |
| Full audit | 10-20 minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
